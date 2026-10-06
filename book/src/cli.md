# deps-cli

`deps-cli` runs `deps-lsp`'s dependency-health checks from the command line — no editor
required. It walks a workspace, routes every manifest it finds through the exact same
14-ecosystem classification pipeline (`deps-engine`) that powers `deps-lsp`'s hover and
diagnostics, and reports outdated/yanked/vulnerable/unsatisfiable/deprecated/license/
mutable-ref-pin findings as a table, as JSON, or as SARIF 2.1.0, with a CI-friendly exit
code.

> **Note:** `deps-cli` implements no classification logic of its own — every verdict comes
> from the same function `deps-lsp` calls for its LSP diagnostics, so a `deps-cli check`
> result and an editor's diagnostics for the same manifest never disagree. See
> [The deps-engine crate](engine.md) for how that sharing works.

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

The image published for the [GitHub Action](github-action.md)
(`ghcr.io/bug-ops/deps-lsp-github-action`) also bundles a prebuilt `deps-cli` binary, fetched
from the matching GitHub release and SHA256-verified at build time — no Rust toolchain to
install, and nothing to trust beyond the image itself. Its default `ENTRYPOINT` is hardcoded to
the GitHub Action's own contract (`deps-cli check --format sarif`, driven by `DEPS_CLI_*` env
vars — see [GitHub Action](github-action.md)), so running `deps-cli` directly means overriding it:

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

`check` and `update` (see [`update` usage](#update-usage) below) are the two `deps-cli`
subcommands. Paths default to the current directory when none are given to `check`.

### Output formats

- **`table`** (default) — human-readable, grouped by manifest path, then by severity
  (error > warning > information > hint) within each file, ending in a one-line
  `Summary: outdated=2 vulnerable=1 ...` count by category.
- **`json`** — a versioned document:

  ```json
  {
    "schema_version": 1,
    "findings": [
      {
        "ecosystem": "cargo",
        "manifest_path": "Cargo.toml",
        "dependency_name": "serde",
        "requirement": "1.0",
        "category": "outdated",
        "severity": "hint",
        "range": { "start": { "line": 4, "character": 0 }, "end": { "line": 4, "character": 10 } },
        "message": "Newer version available: 1.1.0"
      }
    ],
    "summary": { "outdated": 1 }
  }
  ```

  `schema_version` is bumped, and the bump documented as `Breaking` in `CHANGELOG.md`,
  whenever a field is renamed, removed, or its wire type/nullability changes (e.g. a
  sentinel value like `""` becoming `null`); adding a new optional field is not itself
  a bump.
  Note that the JSON schema does **not** carry a finding's OSV advisory id or its
  `https://osv.dev/vulnerability/{id}` link — only `sarif` output does (see below). If your
  tooling needs the advisory id/URL for a vulnerability finding, parse `sarif` output instead
  of `json`.
- **`sarif`** — a SARIF 2.1.0 document. A vulnerability finding becomes its own SARIF rule
  (keyed by its OSV advisory id, e.g. `RUSTSEC-...`/`GHSA-...`) with a `helpUri` to the
  advisory page, a `fullDescription` built from the finding's own message, and a
  `security-severity` score when the OSV scan itself graded that advisory; every other
  category collapses to one rule per category token, using each category's own description
  as its `shortDescription`. Each result carries a `partialFingerprints` entry derived from
  manifest path, dependency identity, rule id, and an occurrence ordinal — not the line
  range — so an unrelated line shift elsewhere in the file doesn't make GitHub treat an
  existing alert as new. `run.automationDetails.id` disambiguates repeated uploads for the
  same commit.

### `--fail-on` categories and exit codes

`--fail-on` takes a comma-separated list of: `outdated`, `yanked`, `vulnerable`,
`unsatisfiable`, `mutable-ref`, `license`, `deprecated`, `other`. It defaults to
`vulnerable,yanked,unsatisfiable` when omitted; an explicit `--fail-on` replaces that default
list rather than extending it. `other` covers every finding that matches none of the seven
specific categories and is never part of the default policy.

**Warning:** `other` also matches informational notices, not only real problems: the offline
notice, the skipped-lookup notice for any manifest without a lock file, an unresolved
self-hosted GitLab host, the dependency-ceiling notice, collapsed registry-fetch failures, and
`sha-comment-mismatch` hints. It therefore fails the run on any manifest without a lock file
and on every `--offline` run, and cannot target one of these findings alone.

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
under-reporting. A single manifest file larger than 10 MB is skipped with a warning rather
than read in full (the same cap `deps-lsp` applies via `fs_probe::read_to_string_capped` — see
[Architecture](architecture.md)).

## Configuration (`deps.toml`)

`deps-cli` reuses `deps-lsp`'s own `PolicyConfig` schema — the same `diagnostics`, `cache`,
`freshness`, `supply_chain`, `registries`, `network`, `license_policy`, `typosquat`, and
`gossip` sections documented in [Configuration](configuration.md) — loaded from a `deps.toml` file instead of
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

`deps-cli` looks for `deps.toml` relative to the walked root when `--config` is not given: if
`check` was given exactly one path, that path's own directory (or its parent, if the path is a
file); if it was given several paths, or none (the implicit `.`), the lookup falls back to the
current working directory instead, since there is no single "the walked root" to prefer among
several. `deps.toml` itself is capped at 1 MB and must be valid TOML matching this schema
exactly (`deny_unknown_fields` at the top level — an unrecognized top-level key rejects the
whole file; an unrecognized key nested inside a known section like `[cache]` is tolerated for
forward compatibility). `--offline` and `--cooldown` override the loaded config for that run
only.

`[gossip] enabled = true` is honored by `check` and `update` when loaded from an explicit
`--config` (see [deps.dev GOSSIP signals](cross-ecosystem/gossip-signals.md)); an auto-discovered
`deps.toml` has it reset to `false`. `[typosquat]` has no effect in `deps-cli` at all: the
typosquat diagnostic is `deps-lsp` only, and a non-default `[typosquat]` section prints a
"has no effect" warning even for an explicit `--config`.

> **Warning:** An auto-discovered `deps.toml` — found by the default lookup, not passed
> explicitly via `--config` — has its `registries`, `network`, and
> `diagnostics.*_enabled` sections (and cache/freshness/license_policy/supply_chain) reset
> to their safe defaults before use; only the seven `*_severity` display values are kept
> (they're cosmetic and can never suppress a `--fail-on` match). This is deliberate: the
> repository a CI job is checking is not a trusted source for the policy that judges it. A
> checked-in `deps.toml` on an attacker-controlled branch must not be able to disable the
> vulnerability scan, force `network.offline` to hide every registry/OSV-derived finding, or
> redirect `GITLAB_TOKEN` to another host via `registries.gitlab_instance_host`. Any section
> ignored this way is named in a warning on stderr. Only a config path given explicitly via
> `--config` — the operator's own choice, not the scanned repository's — is trusted in
> full.

## `update` usage

`deps-cli update <MANIFEST>` reads exactly one manifest, plans a set of version-requirement
edits, and writes them back atomically — the non-interactive counterpart to `deps-lsp`'s
"update all outdated" code lens and per-dependency vulnerability-fix quick action.

```bash
# Update every outdated dependency in Cargo.toml
deps-cli update Cargo.toml

# Only serde, even if other dependencies are also outdated
deps-cli update --package serde Cargo.toml

# Plan without writing, and inspect the machine-readable plan
deps-cli update --dry-run --format json Cargo.toml

# Only OSV-Vulnerable dependencies, via their recommended fix (never plain "latest")
deps-cli update --security-only Cargo.toml

# Ignore rules only take effect from an explicit --config — see below
deps-cli update --config deps.toml Cargo.toml
```

`<MANIFEST>` must resolve to exactly one manifest a registered ecosystem recognizes — a
directory, a shell-glob expansion to more than one path, or an unrecognized file is an
execution error (exit `2`). `update` never walks a tree the way `check` does, so it has no
`--respect-gitignore`/`--follow-symlinks` flags: an explicitly named path is already an
explicit choice.

### Default mode vs. `--security-only`

- **Default mode** targets every dependency `check` would report `outdated`, rewriting its
  declared requirement to the latest matching version — **unless that version was published
  within `freshness.cooldown_secs` of now** (default: 3 days, Dependabot's own default), in
  which case `update` targets the newest already-cooled-down, independently OSV-verified,
  floor-protected fallback candidate instead, when one exists (issue #1528). This is on by
  default and applies even with no `--cooldown`/`--config` given at all: a version that just
  came out is not yet a real recommendation. A fallback candidate is computed whether or not a
  lock-file-resolved in-use version exists: with a lock file, the search floors at the in-use
  version; with no lock file and a range requirement (the majority case for a fresh install),
  it floors at the declared requirement itself, and is only written when doing so provably
  doesn't leave the requirement still admitting a newer, still-cooling version on the next
  unlocked resolve — otherwise `update` falls back to a full skip, reported as a `skipped`
  outcome whose reason names the freshness cooldown window (issue #1544). When the
  fallback candidate is itself OSV-flagged or unverified,
  `update` refuses to write it and exits non-zero naming that version, the same way an unsafe
  `latest` is refused — it never silently falls back to the plain cooldown skip. Disable this
  filter entirely with a `--config` file setting `[freshness] enabled = false`, or narrow the
  window with `--cooldown` (see below). This filter is `deps-cli update`-specific — `check`'s
  own `Outdated` diagnostic and `deps-lsp`'s "update to latest" code action still only
  *annotate* a fresh version's age, never exclude it or substitute a fallback.
- **`--security-only`** targets only dependencies OSV reports vulnerable, rewriting to the
  advisory's own recommended fix (never a plain "latest" pick), and independently
  re-verifies that fix against OSV before writing it. Every vulnerable dependency is
  classified into exactly one of three outcomes:
  - `applied` — the fix was written.
  - `requires-lockfile-update` — the declared requirement already admits the fix, so there
    is nothing to rewrite at the manifest level; a lock-file regeneration step (tracked by
    [#1116](https://github.com/bug-ops/deps-lsp/issues/1116), not yet implemented) is
    needed to actually pull the fixed version in. `update` does not regenerate lock files
    itself.
  - `unfixable` — no independently-verified fix target exists, the registry fetch for that
    dependency failed, the fix target is itself yanked, the declared requirement's syntax has
    no safe single-value rewrite and is confirmed not to already admit the fix target, or the
    declared requirement is too large to safely evaluate. For the last three causes (a yanked,
    confirmed-unsupported-requirement-shape, or oversized-requirement fix target), the table's
    target column and JSON `target` field report that rejected version instead of staying
    empty, so the operator can see what was ruled out even though nothing was written.

  For a registry that does not report yank status at all, the yank check is inert for that
  ecosystem (a documented limitation, not a bug) — such a dependency can still be classified
  `applied` even though its yanked status was never actually checked.

  `--cooldown` (and a `[freshness]` cooldown sourced from `--config`) has no effect under
  `--security-only`: the fix target comes from the advisory, never the freshness-filtered
  registry pick. It is also a no-op in default mode when an explicit `--config` also sets
  `[freshness] enabled = false` — `deps-cli` warns in both cases rather than silently ignoring
  the flag.

### `[update].ignore` (only via `--config`)

```toml
[update]
ignore = [
  { name = "tokio", update_types = ["major"] },  # skip only major bumps
  { name = "legacy-thing" },                     # skip every update, including unclassifiable ones
]
```

`update_types` is one or more of `major`/`minor`/`patch`; omitting it skips every kind for
that dependency, including one `update` cannot classify at all (a GitHub Actions SHA pin, a
Go pseudo-version, a Maven/NuGet range, `*`/`latest`/`workspace:*`, ...) — an unclassifiable
update is always treated as if it met a scoped rule's threshold too, never silently let
through. Names are matched exactly (after normalization), not by wildcard.

**`[update].ignore` is honored only when loaded from an explicit `--config <path>`** —
`update` never auto-discovers a default-location `deps.toml` at all (unlike `check`), so
without `--config` no ignore rule is ever loaded. `--security-only` overrides every ignore
rule outright (never silently applies one) — a security fix is never held back by a routine
maintenance preference, and the plan reports when a rule was overridden rather than applying
it quietly.

Unlike Dependabot's `ignore` (which can retarget a blocked update to the highest version its
own rule still allows), a matching `[update].ignore` rule here skips the dependency entirely
for this run — it is reported `skipped (ignore-rule)` with no edit written at all, never
rewritten to some lesser version.

### Write safety and exit codes

Writes are atomic: a temp file is created in the manifest's own directory
(`O_CREAT|O_EXCL`), permissions are copied from the original before any content is written
(Unix only), the content is fsynced, then renamed over the original. A manifest path whose
final component is itself a symlink is refused before any temp file is created. The manifest
is re-read and byte-compared against the content the plan was computed against immediately
before writing; a mismatch (something else modified the file in the meantime) aborts without
writing.

| Exit code | Meaning |
|---|---|
| `0` | Every selected update was applied, or nothing was eligible, or every non-applied item was a deliberate exclusion — an `[update].ignore` match, a `--package` exclusion, or a version held back by the default-mode freshness cooldown (reported as a `skipped` outcome, see above) |
| `1` | At least one item the run *wanted* to fix but could not — an unsafe/unrecognized span, `requires-lockfile-update`, `unfixable`, or a cooldown-fallback candidate that was itself OSV-flagged/unverified |
| `2` | Execution error — not a single recognized manifest, a registry required to classify the manifest was unreachable, a write/read failure, a symlinked manifest path (refused before any read, not just before the write), stale content detected before write, or `--security-only` combined with `network.offline`/vulnerability scanning disabled |

An ignore rule, a `--package` exclusion, or a freshness-cooldown pause is something the run
deliberately chose to leave alone, not a failure — none of the three ever turn an otherwise-clean
run non-zero on their own. The cooldown pause is automatic (policy-driven), not
operator-requested the way the other two are, but the exit-code treatment is identical: a CI
pipeline must not start failing merely because a dependency's latest release is a few hours
old. An OSV-blocked cooldown-fallback candidate is different: it is a safety refusal, not a
deliberate pause, so it exits `1` the same way a flagged/unverified `latest` does.

**A single unreachable dependency aborts the whole run.** Unlike `check`, which still reports
its other findings alongside exit `2`, `update` treats any one dependency's registry fetch
failure as reason to abort the entire plan before writing anything — a deliberate, stricter
fail-closed choice, not a bug, since a plan built from partial registry data could otherwise
recommend a version that isn't actually the latest.

**A non-zero exit never implies the working tree is unmodified.** A mixed run (some items
applied, others not) exits `1` with the applied edits already written to disk. A wrapper
script deciding what to do with the result (e.g. whether to commit a diff) must inspect each
item's `outcome` field in `--format json` output, never branch on the process exit code
alone.

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

## Using deps-cli in CI

For GitHub Actions specifically, `crates/github-action` ships a ready-made Docker-based action
wrapping `deps-cli check --format sarif`, with SARIF output wired for
`github/codeql-action/upload-sarif` — see [GitHub Action](github-action.md) for inputs,
outputs, exit-code-to-job-failure mapping, and a full workflow example. For any other CI
system, install `deps-cli` as described above and run `deps-cli check --format sarif` (or
`json`/`table`) as an ordinary step, using its [exit code](#--fail-on-categories-and-exit-codes)
to gate the build.

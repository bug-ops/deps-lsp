# deps-cli

`deps-cli` runs `deps-lsp`'s dependency-health checks from the command line — no editor
required. It walks a workspace, routes every manifest it finds through the exact same
15-ecosystem classification pipeline (`deps-engine`) that powers `deps-lsp`'s hover and
diagnostics, and reports outdated/yanked/vulnerable/unsatisfiable/deprecated/license/
mutable-ref-pin/sha-comment-mismatch findings as a table, as JSON, or as SARIF 2.1.0, with a
CI-friendly exit code.

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

# Never touch the network; registry and vulnerability lookups are skipped and reported as offline
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
`unsatisfiable`, `mutable-ref`, `sha-comment-mismatch`, `unknown-ref`, `license`, `deprecated`,
`other`. It defaults to `vulnerable,yanked,unsatisfiable` when omitted; an explicit `--fail-on`
replaces that default list rather than extending it. `sha-comment-mismatch` selects SHA pins
(GitHub Actions/GitLab CI) whose trailing version comment is not confirmed by the repository's
tag index; it matches regardless of the finding's severity and is never part of the default
policy. `unknown-ref` selects tag pins whose ref is a full release that no published tag of the
repository matches, and partial refs such as `@v40` that are neither a published tag nor a branch
(see [GitHub Actions](ecosystems/github-actions.md#unpublished-refs-and-the-unknown-ref-diagnostic-issue-1766));
it is likewise severity-agnostic and never part of the default policy. `other` covers every
finding that matches none of the nine specific categories and is never part of the default
policy.

`unchecked` is not a finding category but a strict, additive run-level gate (see
[Failing on unchecked vulnerability coverage](#failing-on-unchecked-vulnerability-coverage)); it
adds to the other tokens instead of replacing the default list.

**Warning:** `other` also matches informational notices, not only real problems: the offline
notice, the skipped-lookup notice for any manifest without a lock file, an unresolved
self-hosted GitLab host, the dependency-ceiling notice, and collapsed registry-fetch failures.
It therefore fails the run on any manifest without a lock file and on every `--offline` run,
and cannot target one of these findings alone.

**Branch checks and the stderr note.** Deciding that `@v40` names neither a tag nor a branch takes
one request per ref to the forge (GitHub or GitLab), rationed by a per-host allowance: without
`GITHUB_TOKEN`/`GITLAB_TOKEN` only a few checks run per hour, with a token many more. Checks that
are skipped for budget reasons or end inconclusively never produce a finding. With
`--fail-on unknown-ref`, `deps-cli` then prints exactly one line on stderr, and the exit code is
unaffected:

```text
N ref probes skipped (rate budget/inconclusive); set GITHUB_TOKEN/GITLAB_TOKEN in CI
```

In CI, set the token so a mistyped ref cannot slip through unchecked. `--offline` skips every
check, and the same checks also decide whether a commit-pinned action ahead of its latest release is
up to date (see [GitHub Actions](ecosystems/github-actions.md#commits-ahead-of-the-latest-release-issue-1725)).

**Vulnerability data not checked.** A dependency whose registry cannot be verified as a public
mirror is never sent to OSV: an npm dependency routed by the top-level `registry=` entry in `.npmrc`
(valid or not; an explicit `registry=https://registry.npmjs.org/` is the public registry and is scanned),
a Deno `deno.json` `npm:` import routed by that same top-level `registry=` to a non-public registry (an `@scope:registry=` entry stays private and silent),
a PyPI dependency whose primary `--index-url` or uv `default = true` index replaces public PyPI (an invalid or
blocked `default = true` index counts, with or without extra indexes; it fails closed to an unverifiable custom registry), a NuGet
dependency whose `<clear/>`-replaced feed chain has no public feed, a Go module whose every `GOPROXY` hop was rejected (including one that also
matches `GONOSUMDB`), or a Go module matched only by a `GOPRIVATE`, `GONOPROXY` or `GONOSUMDB` pattern of a `go.env` found through `PATH`
(not `GOROOT`): that file is not operator-trusted, so the module counts as reaching a registry not verified as a public mirror. Such a dependency produces no finding, so `--fail-on vulnerable` cannot see it.
When the run skipped any, `deps-cli` prints exactly one line on stderr and the exit code is
unaffected:

```text
deps-cli: note: vulnerability data not checked for N dependencies (registry not verified as a public mirror)
```

Scoped npm registries (`@scope:registry=`), modules excluded by `GOPRIVATE`, `GONOSUMDB` or
`GOSUMDB=off` while a usable `GOPROXY` route exists, and VCS or path dependencies are private by
declaration and stay silent. In the editor, hover shows a "Vulnerability data not checked" footer
only for dependencies whose registry it can resolve (an npm dependency routed by a valid top-level
`registry=`); an invalid npm entry and a Go module with every hop rejected get no footer, only the
CLI note.

### Exempting advisories

`--advisory-exemptions <PATH>` reads an operator-owned file of accepted advisories (the format is
described under [Exempting an advisory](configuration.md#exempting-an-advisory-operator-file)):

```bash
deps-cli check --advisory-exemptions ~/.config/deps-lsp/advisory-exemptions.toml
```

- The file is never discovered automatically and is not part of `deps.toml`. A missing or invalid
  file exits `2` and the message names the path, not its content.
- An exempted advisory no longer counts as `vulnerable`, so `--fail-on vulnerable` passes when every
  advisory of a dependency is exempted. Each such dependency instead gets one informational finding
  (`N advisories exempted by operator config: ...`) in the `other` category, so `--fail-on other`
  fails on it and SARIF reports it as a `note`.
- `MAL-` (confirmed malware) advisories can never be exempted, and an expired entry is ignored.
- **Untrusted pull requests:** with `pull_request_target` or any workflow that checks out fork code,
  a file path inside the checked-out tree is attacker-controlled. Keep the exemption file outside
  the checkout (a runner path, a separate repository checkout, or a secret written to a temp file).
- The editor reads the user config directory automatically; the CLI needs this flag by design so CI
  input is explicit. For local parity pass the same path.

### Failing on unchecked vulnerability coverage

`--fail-on vulnerable` only sees dependencies that OSV actually scanned. `--fail-on unchecked`
closes that blind spot: the run exits `1` when vulnerability data was not checked for at least one
dependency, so a green CI result means every dependency was covered.

```bash
# Default categories (vulnerable,yanked,unsatisfiable) plus the coverage gate
deps-cli check --fail-on unchecked

# Fail on outdated dependencies and on any coverage gap
deps-cli check --fail-on outdated,unchecked
```

The gate is additive: `--fail-on unchecked` alone keeps `vulnerable,yanked,unsatisfiable`, and
`--fail-on outdated,unchecked` fails on `outdated` plus the gate. A dependency counts as unchecked
when:

- its registry cannot be verified as a public mirror (the case in the note above);
- its OSV query failed or timed out (see below), which also fails `--fail-on vulnerable`;
- its scan did not complete: the OSV result was truncated, or a version or tag lookup stayed
  unresolved;
- it is missing from a lock file that was found (a manifest edit that was never relocked) and so has
  no concrete version to match;
- not every lock-file entry satisfying its requirement was scanned (more than the 16 nearest, or an
  entry's version could not be matched), even when the scanned entries already carry advisories;
- it falls beyond the per-document dependency ceiling (5000), so it was never scanned.

These are not gaps: `peerDependencies` entries (never written to a lock file), dependencies that
are unlocked by design, VCS and path dependencies, and a project with no lock file at all. The
gate also fails when vulnerability scanning is switched off with
`diagnostics.vulnerabilities_enabled = false`, because then nothing was checked; `deps-cli` prints a
stderr note naming the setting. When dependencies are unchecked, the stderr note lists each gap
class, and for incomplete tag lookups it suggests setting `GITHUB_TOKEN`/`GITLAB_TOKEN`.

**OSV outage.** When `vulnerable` is among the gated categories (it is in the default set) and an
OSV query fails (network error, timeout, server error, or the scan deadline expiring before the query ran), the run exits `1`, the same code as
`--fail-on unchecked`, and prints `vulnerability data unavailable for N dependencies (OSV query
failed)` on stderr. A broken OSV connection therefore never looks like a clean scan. This applies to
`--fail-on vulnerable` and the default set alike; a run that does not gate `vulnerable` (for example
`--fail-on outdated`) is unaffected. If scanning is inactive instead (`--offline`, or
`diagnostics.vulnerabilities_enabled = false`), no query is made: the exit code does not change,
but `deps-cli` prints a stderr note that `--fail-on vulnerable` checked nothing. Use
`--fail-on unchecked` to make that case fail too.

`--fail-on unchecked` cannot be combined with `--offline` (or `network.offline = true`): an offline
run checks no vulnerability data, so `deps-cli` exits `2` with an error instead of failing every
dependency.

| Exit code | Meaning |
|---|---|
| `0` | Clean — no finding matched the `--fail-on` policy |
| `1` | Policy violation — at least one finding matched `--fail-on`, `--fail-on unchecked` found a coverage gap, or an OSV query failed while `vulnerable` is gated |
| `2` | Execution error — `--fail-on unchecked` combined with offline mode, a registry was unreachable, a `deps.toml`/manifest failed to parse, or a walked path was unreadable |

An unreachable registry (DNS failure, connect timeout after 10 seconds, refused connection) is an
execution error: `deps-cli check` exits `2` and reports "Registry lookup failed". A registry that the
access policy blocks, for example a private address without an allowlist entry, is different: it is a
policy decision, reported as an informational `other` finding naming the policy and the
[allowlist hint](configuration.md#private-registry-allowlist), and the run exits `0` unless you add
`--fail-on other`. Guarded registry hosts bypass the system proxy unless
`DEPS_LSP_WORKSPACE_REGISTRY_PROXY=proxy` is set, while [operator-owned registries](configuration.md#operator-owned-registries) always follow it (see
[Proxies and guarded registry traffic](configuration.md#proxies-and-guarded-registry-traffic));
`deps-cli` prints one stderr line at startup when it detects a system proxy.

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

The walk skips every dot-prefixed entry except two kinds: a file whose name exactly equals a
registered ecosystem manifest filename (for example the root or a nested `.gitlab-ci.yml`),
and the dot-directories an ecosystem claims (`.github`, `.gitlab`). Pattern-matched names
such as `.x.csproj` or `.dev.requirements.txt` are not admitted, and `.git` and other
dot-directories stay out of the scan.

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
several.

A file named `deps.toml` can also be a Gradle version catalog. A file you check by name is never
loaded as configuration. A `deps.toml` found by this lookup that a `settings.gradle(.kts)`
declares as a catalog is not loaded either: the run uses the default configuration and prints

```text
deps-cli: warning: <path> was not loaded as configuration: a Gradle settings file declares it as a version catalog; pass a configuration file with --config
```

`deps.toml` itself is capped at 1 MB and must be valid TOML matching this schema
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
> `diagnostics.*_enabled` and `diagnostics.suppress`/`diagnostics.ignore` (and cache/freshness/license_policy/supply_chain) reset
> to their safe defaults before use; only the seven `*_severity` display values are kept
> (they're cosmetic and can never suppress a `--fail-on` match). This is deliberate: the
> repository a CI job is checking is not a trusted source for the policy that judges it. A
> checked-in `deps.toml` on an attacker-controlled branch must not be able to disable the
> vulnerability scan, force `network.offline` to hide every registry/OSV-derived finding, or
> redirect GitLab host resolution via `registries.gitlab_instance_host`. (`GITLAB_TOKEN` is never
> sent to that host: it is bound to `gitlab.com` or the `GITLAB_TOKEN_HOST` environment variable,
> so an explicit `--config` does not authenticate a self-hosted host by itself.) Any section
> ignored this way is named in a warning on stderr. Only a config path given explicitly via
> `--config` — the operator's own choice, not the scanned repository's — is trusted in
> full.

> **Note:** `registries.workspace_registries = "all"` reaches private hosts only if they are listed
> in the `DEPS_LSP_PRIVATE_REGISTRY_HOSTS` environment variable (see
> [Configuration](configuration.md#private-registry-allowlist)), also with an explicit `--config`.
> An allowlisted host is reachable on any port, so list registry hosts or narrow CIDRs only. In the
> GitHub Action, set it in the step's `env:`. Without the variable, `"all"` behaves like
> `"public_only"` and `deps-cli` prints a warning on stderr.

> **Note:** `registries.swift_keychain_credentials` is not supported in `deps-cli`, which cannot
> answer a macOS Keychain access prompt: an explicit `--config` with it enabled prints a warning
> and runs with it disabled. See [Swift macOS Keychain credentials](ecosystems/swift.md#macos-keychain-credentials).

> **Note:** `registries.swift_scm_to_registry = "replace"` works in `deps-cli` only from an explicit
> `--config` (an auto-discovered `deps.toml` has its `registries` section reset, like the other
> settings above). `check` and `update` wait for every identity lookup and print one stderr note
> when some did not complete. See
> [Replacing Source Control with a Registry](ecosystems/swift.md#replacing-source-control-with-a-registry-issue-1757).

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
  window with `--cooldown` (see below).

  The package manager's own release-age window is honored the same way, even with
  `[freshness] enabled = false`: `update` writes the newest eligible version, and reports the
  dependency as `within-native-cooldown` only when there is none. `honor_native_cooldown = false`
  turns that off. A skipped item reports its current and target version. `check` judges
  `outdated` against the same eligible version, see
  [Release-Age Holds](cross-ecosystem/version-diagnostics.md#release-age-holds).

  For npm and Deno, the fallback edit keeps the requirement operator (`^`, `~`, `=`). When a
  `^` range would still admit the newer version that was withheld (because it is cooling down or
  flagged), `update` retries once with an exact pin of the fallback version instead of skipping
  the dependency, and writes it only if that exact pin passes the same check.
- **`--security-only`** targets only dependencies OSV reports vulnerable, rewriting to the
  advisory's own recommended fix (never a plain "latest" pick), and independently
  re-verifies that fix against OSV before writing it. When the registry marks that fix
  version deprecated (npm, Composer, Deno `npm:`), the target moves to the next fresh
  plain release on the same compatibility line (never across a major or onto a
  GOSSIP-excluded release, and skipping the registry's latest release while it is inside the
  default three-day cooldown), which is verified the same way; if that fails the dependency
  is not rewritten to the deprecated version. Every vulnerable dependency is classified into
  exactly one of three outcomes:
  - `applied` — the fix was written to the manifest, or (with `--lockfile regenerate` for
    Cargo, npm, pnpm, Yarn Berry, Bun, Go, PyPI (including Pipenv), Bundler, Deno, Composer, Dart, Gradle and SwiftPM, and NuGet for edited pins only) the lock file was moved to the fix target because the declared
    requirement already admits it; the report's reason tells the two apart.
  - `requires-lockfile-update` — the declared requirement already admits the fix, so there
    is nothing to rewrite at the manifest level, and the lock file still resolves a vulnerable
    version. Pass `--lockfile regenerate` to let `update` move the lock file (Cargo, npm, pnpm,
    Yarn Berry, Bun, Go, PyPI (including Pipenv), Bundler, Deno, Composer, Dart, Gradle and SwiftPM); for Maven,
    Yarn Classic and a lock-file-only pin in NuGet,
    update the lock file yourself.
  - `unfixable` — no independently-verified fix target exists, the registry fetch for that
    dependency failed, the fix target is itself yanked, the declared requirement's syntax has
    no safe single-value rewrite and is confirmed not to already admit the fix target, or the
    declared requirement is too large to safely evaluate, or a commit (SHA) pin's fix version
    has no matching release in the repository's complete tag list (GitHub Actions, GitLab CI;
    for a GitLab `component:` include, its release list), so the pin cannot be rewritten and
    still points at the vulnerable commit, or (`--lockfile regenerate` with `--security-only`) the package manager would
    resolve a version inside the freshness cooldown window once the edit is written, so the edit
    is withheld. A missing, cold or truncated tag list cannot prove that, and is reported as no verified fix instead. For the
    last five causes (a yanked, confirmed-unsupported-requirement-shape, oversized-requirement,
    no-release-tag or withheld-by-cooldown fix target), the table's target column and JSON `target` field report
    that rejected version instead of staying empty, so the operator can see what was ruled out
    even though nothing was written.

  For a registry that does not report yank status at all, the yank check is inert for that
  ecosystem (a documented limitation, not a bug) — such a dependency can still be classified
  `applied` even though its yanked status was never actually checked.

  `--cooldown` (and a `[freshness]` cooldown sourced from `--config`) does not change the fix
  target under `--security-only`: it comes from the advisory, never the freshness-filtered
  registry pick (with `--lockfile regenerate` the window still rejects a lock-file-only move onto
  a version inside it). It is also a no-op in default mode when an explicit `--config` also sets
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

### Regenerating the lockfile (`--lockfile regenerate`)

By default `update` only edits the manifest (`--lockfile skip`). With `--lockfile regenerate`,
after a successful write it runs the ecosystem's own tool in the manifest's directory and checks
the fresh lockfile against every applied version:

| Ecosystem | Tool run | Checked against the lockfile |
|---|---|---|
| Cargo | `cargo update --workspace` (only when a manifest was edited), then `cargo update --package=<name>@<class> --precise=<version>` per update | the lockfile holds exactly the target |
| npm (`package-lock.json`) | `npm install --package-lock-only --ignore-scripts --no-audit --no-fund` (manifest edits), then `npm update --no-save --package-lock-only --ignore-scripts --no-audit --no-fund <names>` (lock-file-only fixes) | a locked version satisfies the declared requirement and is at least the target |
| pnpm (`pnpm-lock.yaml`) | `pnpm install --lockfile-only --ignore-scripts --no-frozen-lockfile`, then `pnpm update --lockfile-only --no-save --ignore-scripts <names>` | same as npm |
| Yarn Berry (`yarn.lock`, Yarn 2+) | `yarn install --mode=update-lockfile` (manifest edits), then `yarn up --recursive --mode=update-lockfile <names>` (lock-file-only fixes), with scripts disabled | same as npm |
| Go | `go get -- <module>@<version>` (with `GOWORK=off`) | `go.sum` holds the module's content checksum for the target |
| PyPI (`uv.lock`) | `uv lock --no-build --no-python-downloads --upgrade-package <name>==<version>` per update | the lockfile holds exactly the target |
| Bundler (`Gemfile.lock`) | `bundle lock` (manifest edits), then `bundle lock --conservative --update <names>` (lock-file-only fixes) | a locked version satisfies the declared requirement and is at least the target |
| Deno (`deno.lock`) | `deno install --lockfile-only --lock=./deno.lock` (manifest edits), then `deno update --compatible --lockfile-only --lock=./deno.lock <names>` (lock-file-only fixes) | same as Bundler |
| Bun (`bun.lock`) | `bun install --lockfile-only --ignore-scripts` (manifest edits), then `bun update --lockfile-only --ignore-scripts <names>` (lock-file-only fixes), `package.json` restored and `bun install --lockfile-only --ignore-scripts` again | same as npm |
| PyPI (`poetry.lock`) | `poetry lock` (`poetry lock --no-update` on Poetry 1.x), then `poetry update --lock <names>` (lock-file-only fixes), with `--no-interaction --no-plugins` | a locked version satisfies the declared requirement and is at least the target |
| PyPI (`Pipfile.lock`) | `pipenv upgrade --lock-only <names>` once for every pin (the `Pipfile` is not edited) | a locked version satisfies the `Pipfile` requirement and is at least the target |
| PyPI (`pdm.lock`) | `pdm lock --update-reuse` (manifest edits), then `pdm update --no-sync <names>` (lock-file-only fixes) | same as Poetry |
| Composer (`composer.lock`) | `composer update <vendor/name...> --no-install --no-scripts --no-plugins --no-interaction` with `COMPOSER=composer.json` | same as Poetry |
| Dart / Flutter (`pubspec.lock`) | `dart pub get --no-example` (manifest edits), then `dart pub upgrade --no-example <names>` (lock-file-only fixes); `flutter pub` instead when a dependency comes from the Flutter SDK | same as Poetry |
| NuGet (`packages.lock.json`) | `dotnet restore <project> --use-lock-file --no-dependencies --force --disable-build-servers -p:RestoreLockedMode=false` (the final check of a floating lock-file-only pin runs `--locked-mode` instead of the property) | same as Poetry |
| Gradle (`gradle.lockfile`, `*.lockfile`) | `gradle --no-daemon --console=plain :<path>:dependencies ... --update-locks <group:artifact,...>` at the build root, one task per project directory that owns a lock file | the lockfile holds the target (a lock-file-only pin may hold a newer version) |
| SwiftPM (`Package.resolved`) | `swift package resolve` (manifest edits), then `swift package update <identity>` (lock-file-only fixes) | same as Poetry |

For PyPI, Bundler, Deno, Composer, Dart and Swift the lock file must sit beside the manifest, and for
PyPI the lock file (`uv.lock`, `poetry.lock` or `pdm.lock`) must sit beside a `pyproject.toml`, and
`Pipfile.lock` beside a `Pipfile`. Pipenv re-resolves only the named packages and never modifies the
`Pipfile` (a `Pipfile` the tool does rewrite ends the run as `manifest-changed` and is restored). It
cannot be asked for an exact version, so it locks the newest release the `Pipfile` admits, and the
pin is checked as "at least the target and satisfying the `Pipfile` requirement"; a cooldown-fallback
target is refused (`cooldown-fallback-target`). deps-cli sets `PIPENV_VENV_IN_PROJECT=0`, `PIPENV_DONT_USE_PYENV=1` and
`PIPENV_DONT_USE_ASDF=1`, and refuses a `.venv` file or symlink beside the `Pipfile`
(`unsupported` with the reason `saved-virtualenv`); the repository's `.env` is not loaded
(`PIPENV_DONT_LOAD_ENV=1`). Pipenv still runs repository-controlled interpreters, which the trust
model below covers. An old Pipenv that rejects
`--lock-only` ends as `tool-failed` with the lock file restored. `--no-build` means a dependency that
exists only as a source distribution fails a uv run (the lock file is restored, see below). Poetry and
PDM may build source distributions to read their metadata, and Poetry can prompt for a keyring in a
headless session. Poetry 1.x runs `lock --no-update`. The version is probed with
`poetry --no-plugins --version`; a Poetry older than 1.2 (which rejects `--no-plugins`) reports
`unsupported` with the reason `tool-too-old` and nothing is written. A failing probe is reported the
same way, including a Poetry that is broken for another reason, and is never retried without
`--no-plugins`, since a plain probe would load plugins the repository controls. PDM runs with `--skip=:all` (its `pre_lock`/`post_lock` hooks are skipped) and
`PDM_IGNORE_SAVED_PYTHON=1` (a committed `.pdm-python` interpreter is not used), but PDM has no flag
that disables plugins. When no environment exists, PDM creates `.pdm-python`, and `.venv` unless `PDM_USE_VENV=0` is set, in the
manifest's directory: untracked residue, or a rewritten tracked `.pdm-python`, which the `--open-pr`
gate then refuses. Composer runs with
`--no-plugins` and `--no-scripts` but its audit step is not disabled, and without `-w`/`-W`: a conflict
that needs an unnamed package makes it exit non-zero, reported as `tool-failed` with the lock file
restored. Composer's own release-age or blocking settings may also refuse a target, which ends the
same way. A Dart project that declares a
pub workspace (a top-level `resolution:` key, or a lock file in an ancestor directory) reports
`unsupported`; a Flutter run may also write generated platform files, which `--open-pr` refuses if
they are tracked. Dart and Flutter are chosen by the dependencies' SDK source, not by
`environment.flutter`.

A cooldown-fallback version is pinned exactly in the manifest for the run: uv, npm, pnpm, Bun and
Bundler accept it (npm, pnpm, Bun and Bundler write the exact pin, run the tool, restore the
declaration and re-run it so the lock file keeps the pinned resolution, then check the result).
Yarn Berry and Deno accept it too, but restoring the declaration would make them re-resolve to the
newest release, so after the first install they rename the lock key back to the declared range
(Yarn: only the column-0 header descriptor; Deno: the `npm:` or `jsr:` key and the `workspace.dependencies` value) and install again, so
the lock keeps the pinned version. This needs a plain version range as the declaration: a protocol,
alias or comparator set still reports `unsupported` with `cooldown-fallback-target`, a lock that
cannot be re-keyed fails as `fallback-pin-not-kept`, and the lock file is restored. Poetry, PDM,
Composer, Dart, Swift, NuGet, Gradle and Pipenv refuse a fallback target.

**Refusals by ecosystem.**
- **Bun:** only a standalone project runs. A lock-file-only pin runs `bun update --lockfile-only`,
  which rewrites the declared range in `package.json`, so `package.json` is written back and
  `bun install --lockfile-only` runs again, leaving the declaration untouched and the lock moved. A
  Bun older than the one that accepts `--lockfile-only` for `update` ends as `tool-failed`, restored.
  A Bun workspace member reports `workspace-member-lockfile`.
- **NuGet:** lock-file-only pins regenerate without a cooldown bypass, and never with
  `--force-evaluate`. A pin on a floating declaration (`*`) is pinned exactly for one restore, then the
  declared requirement is put back, the `requested` field in `packages.lock.json` is reset to it, and a
  locked-mode restore (`--locked-mode`) proves the manifest and lock file agree. A pin whose declared
  floor already equals the fix needs only the restore. Any other lock-file-only pin stays untouched and
  `requires-lockfile-update`; a plan made of such pins alone reports `lockfile-only-update-unsupported`
  before any tool runs. The resolving restore sets `-p:RestoreLockedMode=false`, so a project that sets
  `RestoreLockedMode` in its project file no longer fails with `NU1004`. A manifest edit makes `dotnet restore` re-resolve every floating dependency of
  the project, which would bypass the release-age window, so a floating or bounded requirement of any
  other package refuses the run as `other-floating-requirements`. The check reads the manifest and the
  lock file, so floating requirements that come from `Directory.Build.props`, a `ProjectReference` or
  central package management are caught too. Pin those dependencies to exact versions to enable
  regeneration. A project using `Directory.Packages.props` as the edited manifest reports
  `central-package-versions`; `packages.config` has no regeneration (`no-lockfile-present`).
- **Gradle:** the lock files of the build are found by a bounded walk from the build root (the nearest
  ancestor with `settings.gradle[.kts]`, otherwise the project directory); under `--open-pr` the
  build root must lie inside the repository (an outer `settings.gradle` reports
  `lockfile-outside-repository`). A build with more than 512 lock files reports
  `lockfile-set-too-large`. A build with locks in `buildSrc/` or in an included build is refused
  (`lockfile-ownership-mismatch`): Gradle applies `--update-locks` to the buildSrc build as well, so
  the lock set cannot be updated consistently. Run the regeneration inside that build instead. A build on the legacy
  `gradle/dependency-locks` layout is migrated to `gradle.lockfile` first (see *Legacy lock layout*
  below). The tool is the `gradle` on `PATH`; the
  Gradle wrapper is never used, so a build pinned to a wrapper version needs a compatible `gradle` on
  `PATH`. The tool runs once at the build root with one `:<path>:dependencies` task per distinct
  project directory that owns a lock file (the root project is `:dependencies`). The project path is
  derived from the lock file's directory relative to the build root and may contain only
  `A-Za-z0-9-_.` components, otherwise the run is refused; the directory name is assumed to be the
  project name, so a build that remaps `projectDir` in `settings.gradle` fails verification and the
  lock files are restored. Every lock file of the build is snapshotted and, with `--open-pr`,
  published. Verification is exact for a pin made by a manifest edit and for a cooldown-fallback pin. A
  lock-file-only pin (a dynamic requirement such as `32.+` that already admits the fix) may instead
  hold a newer version than the target by Gradle's own ordering, so a security-only fix that resolves
  newer is accepted. A version below the target, or one that cannot be ordered, fails with `version-mismatch` and the lock files are restored. Every
  other coordinate must stay as it was: if `--update-locks` gains or loses a coordinate of another
  module, the run fails as `lock-state-drift` and the lock files are restored. This includes a lock file that lacks a configuration holding other modules, because `--update-locks` would resolve and lock those modules anew. `--update-locks` creates a
  `gradle.lockfile` for a locked project that had none; the run snapshots that file as absent,
  includes it in the drift check, reports it as created and removes it again if the run fails.

  **Legacy lock layout.** Gradle 7 and later cannot write `gradle/dependency-locks`, so `update`
  migrates it to `gradle.lockfile` before pinning. It then compares the migrated state with the legacy
  one for every configuration the legacy files held. If the migration would move unrelated modules,
  the run fails as `lock-state-drift` and every file is restored. Legacy lock files are deleted afterwards and reported as
  `migrated` (the configuration moved into `gradle.lockfile`), `stale-empty` or `stale-dropped` (Gradle no
  longer resolves the configuration; `stale-dropped` also discards locked coordinates, so a task that
  still resolves it runs unlocked). When the same run also edits a version, the
  migration happens first at the currently locked versions and the edit is applied afterwards, so a
  version update on a legacy project works in one run. The migration holds each edited dependency
  at its single legacy-locked version, so the drift guard stays exact; a dependency that no relevant
  legacy lock holds keeps its edited declaration. An edited dependency locked at several versions, or
  without a single declaration carrying a version, is refused before anything runs as `legacy-lock-layout`.
  The message advises migrating once with `gradle :<project>:dependencies --update-locks <group:module>`,
  committing the result and rerunning. A `gradle/dependency-locks` directory holding no `*.lockfile` file is
  ignored. Two layouts are refused with `legacy-lock-layout` and a message saying what to do: a legacy
  directory beside an existing `gradle.lockfile` (Gradle ignores the directory; delete it; the message
  names the project's own lock file and directory), and a legacy
  `settings-*.lockfile` (not migrated automatically).
- **Yarn Classic:** always `unsupported` (`yarn-classic`).
- **Any ecosystem:** a lock file that is a symlink reports `lockfile-symlink`, and one whose real path
  is outside the repository root reports `lockfile-outside-repository`.

A `--security-only` fix whose declared requirement already admits the target (a caret range,
say) needs no manifest edit: with `--lockfile regenerate` only the lock file moves, and the item
becomes `applied` once the regenerated lock file holds the target. `npm update` and `pnpm update`
always pick the newest in-range release, so a newer version also counts, but only when every
advisory affecting the locked version (captured from OSV with the plan, no extra query) places that
version outside its affected ranges (an advisory introduced by a release between the fix and the newer version is not checked, and the next run reports it); the item then reports the version the lock file now holds. When a
newer version cannot be cleared (it lies in a later affected range, the ranges are not SemVer or
could not be evaluated, or the advisory list was truncated), the item stays
`requires-lockfile-update` (exit `1`) and its reason says the lock file now resolves that version
and it needs a manual review; the report's `lockfile` object shows it as `newer`. Names handed to `npm update`
and `pnpm update` are validated (pnpm treats them as patterns, so `*` and a leading `!` are
refused with exit `2`). `go get` may also raise the module's `require` line in `go.mod`.

A tool that cannot pin an exact version (`npm update`, `pnpm update`, `pipenv upgrade --lock-only`
and the like) may lock a newer in-range release that is still inside the freshness cooldown
window, and `update` accepts such a pin only when that version is outside the window. When the tool
lands inside it, `update` restores the lock files from the snapshot and withholds the held fixes:

- A held lock-file-only pin stays `requires-lockfile-update` (exit `1`), with a reason that names
  the resolved version and the window.
- A held pin that edits the manifest is not written: the edit is removed from the manifest and the
  reason names the resolved version and the window. In the default mode the item is `skipped`
  (exit `0`), like any release the cooldown window holds back. With `--security-only` it is
  `unfixable` (exit `1`) and its target shows in the `target` column.
- The tool runs once more for the remaining pins, and their fixes apply.
- When every pin is held, nothing is rerun: the manifest and the lock files stay unchanged and the
  table's lockfile line reads `not applicable — every fix resolved to a version inside the
  freshness cooldown window and was withheld`, and the JSON `lockfile.reason` is
  `all-withheld-by-cooldown`.

With `--open-pr`, a withheld fix and its version never reach the proposal; a run that settles
nothing opens none.

The run fails with `cooldown-held-version` (exit `2`, lock files restored) only when the manifest
changed during the run (or cannot be rewritten), or when the single retry lands inside the window again. A manifest edit that the retry holds is written back out of the manifest before the run fails, so it is not left applied. A version without
a known publish time, or any version with freshness disabled, is not held back, and a
cooldown-fallback target is unaffected because it is pinned exactly. `update` checks the window
itself; the package manager's own cooldown setting is not consulted.

**npm and pnpm workspace members.** When the manifest is a member of an npm or pnpm workspace and the
lock file sits in the workspace root, a plain run regenerates that root lock file with the member
selected (`--workspace=./<member>` for npm, `--filter=./<member>` for pnpm). For pnpm the member must
be listed by the workspace (probed before anything is written), otherwise the report is `unsupported` with the reason
`workspace-member-lockfile`. Ownership of the lock file must be proven, otherwise the report is
`unsupported` with the reason `lockfile-ownership-mismatch`. For pnpm the workspace root reported by
`pnpm root -w` must equal the directory holding the lock file. For npm no tool is asked (`npm prefix`
is not used); ownership is read from the lock file: the root `package.json` declares
`workspaces`, no outer workspace contains it, a lock file version 2 or 3 lists the member under
`packages`, and a workspace pattern matches the member (a `!`, `..`, absolute, empty or invalid
pattern fails the whole set). `--open-pr` accepts members: the root lock file is published with the
manifest, provided it lies inside the repository.

**Go workspaces.** A `go.work` no longer blocks regeneration: `go get` runs with `GOWORK=off`, so
only the module's own `go.mod` and `go.sum` change.

**Yarn.** Yarn Berry (2 and later) is regenerated. The version is probed first with
`yarn --version`; Yarn Classic (1.x) reports `unsupported` with the reason `yarn-classic`. Workspace
members and standalone roots that declare workspaces are found with `yarn workspaces list --json` at
the root (the member must be listed exactly once, with no outer root); the tool runs at the root.
Yarn re-serializes the `package.json` of every workspace on `install` and `up`, so all workspace
manifests are captured first and written back byte for byte when their JSON content is unchanged;
otherwise the report says `manifest-changed` and everything is restored. A listing too large for the
probe reports `lockfile-set-too-large`.

**Go vendored modules.** A module with `vendor/modules.txt` is regenerated: `go get` and
`go mod vendor -o <scratch>` run with `GOFLAGS=-mod=mod` (replacing an inherited `GOFLAGS` for these
two commands only). The `vendor` tree is not part of the lock-file snapshot. deps-cli builds the new
tree in a scratch directory next to `vendor/`, checks `go.sum` and `vendor/modules.txt` against the
applied versions, and only then replaces `vendor/` with two renames, so a failed or interrupted run
leaves the previous `vendor/` untouched; `go.mod` and `go.sum` are restored from the snapshot. Under
`--open-pr`, `vendor/` must be tracked in `HEAD`, and a failed publish restores it from git. A run
killed with SIGKILL between the two renames can leave a `.deps-cli-vendor-*` directory beside
`vendor/`. A `vendor` that is a symlink or not a directory reports
`lockfile-symlink`; one outside the repository reports `lockfile-outside-repository`.

A regeneration that migrated a legacy Gradle layout adds a `migration` object to the `regenerated`
lockfile object: `created` (the new lock files) and `removed` (each deleted legacy file with its
`removal`: `migrated`, `stale-empty` or `stale-dropped`). The table output prints a matching summary line.
The key is omitted when no migration happened.

The JSON report always has a `lockfile` object tagged by `status` (`regenerated`, `skipped`,
`not-applicable`, `unsupported`, `failed`). A failed regeneration prints the full report and
exits `2`; the manifest edit stays on disk, and the lock files the run touched are restored (see
below). Nothing runs under `--dry-run` or `--offline`. Maven (which has no lock file format) and Yarn Classic
report `unsupported`, as do a symlinked lockfile, a lockfile outside the repository, a
lockfile in an ancestor directory for PyPI, Bundler and Deno (workspace members; for Deno also any
ancestor `deno.jsonc`, a `deno.json` with `workspace`, or a `package.json` with `workspaces`), and the
refusals listed above. A binary `bun.lockb` is not recognized as a lockfile, so a Bun project
with only that file reports `no-lockfile-present`.

**Check-then-spawn window.** Workspace, ownership and symlink checks run before the tool starts, so
a change made to the tree in between is not noticed.

**Trust model.** Lockfile regeneration runs the ecosystem's tool on a checkout you trust. Repository
files such as `.pnpmfile.cjs`, `Gemfile`, Yarn plugins and `yarnPath`, and `.cargo/config.toml` can
execute code, so run `--lockfile regenerate` only on repositories you trust. pnpm executes
`.pnpmfile.cjs` even with `--ignore-scripts`. The tool also reads the repository's other
configuration (`rust-toolchain.toml`, `.npmrc`, the `go.mod` toolchain directive), its network
traffic is not subject to deps-cli's registry policy, child processes inherit the full environment
(so tokens in it are readable by those files), and corepack may download a package manager silently.
Bundler has no version override and may switch to the Bundler version recorded in `Gemfile.lock`.
The newer tools run repository code too: Gradle executes the build's settings and build scripts,
`dotnet restore` evaluates MSBuild files (`Directory.Build.*` and custom targets), SwiftPM evaluates
`Package.swift` of the project and its dependencies (not sandboxed on Linux), PDM may load plugins
(its hooks and a saved interpreter are disabled, see above), and Composer can fetch from the `vcs`
repositories the manifest declares (its scripts and plugins are disabled). Poetry runs with plugins
disabled. Pipenv resolution may build source distributions (running the `setup.py` or build backend of
dependencies) and has no option to disable that.

**Failure kinds.** A failed regeneration carries a typed kind. File operations of the run (rewriting a lock
file, moving a vendor directory, creating a scratch directory) fail as `io` with the
operation and path instead of `manifest-changed` or `spawn`; an unreadable lock file still reports `lockfile-unreadable`. A failed manifest write-back restores
the lock snapshot as well. `lockfile-pin-not-kept` means the
lock file could not be put back to the declared requirement after an exact pin (NuGet: the lock holds no
unambiguous entry or no original request to restore, or does not parse), and the lock file is restored.
`lock-state-drift` means a Gradle lock regeneration or layout migration would have changed the locked
coordinates of a module other than the pinned ones. `fallback-pin-not-kept` means a cooldown-fallback pin could not be kept in
the lock (Yarn Berry or Deno re-key refused or failed), and the lock file is restored.
`cooldown-held-version` means the tool locked a version inside the freshness cooldown window and
the single retry without the held pins held again, or the manifest changed during the run or could not be rewritten; the
lock files are restored.
The report carries the first held package as `package` and its version as `found`, and a `held`
array with one `{"package", "found"}` entry per held pin, the first included; `held` is omitted for
every other failure kind. The message lists any further held pins.

The `package`, `expected` and `found` fields of a failed `lockfile` object depend on the kind:

| Kind | `package` | `expected` | `found` |
|---|---|---|---|
| `version-mismatch` | the package | expected version | locked version, or `null` |
| `cooldown-held-version` | first held package | `null` | first held version |
| `lockfile-pin-not-kept`, `fallback-pin-not-kept` | the pinned package | the pinned target version | `null` |
| `lock-state-drift` | the drifted `group:artifact:version` coordinate | `null` | `null` |
| any other kind | `null` | `null` | `null` |

`lock-state-drift` adds two fields that appear for no other kind: `configuration` (the Gradle
configuration that changed) and `change` (`gained` or `lost`).

**Known limits.** `go get` may raise indirect requirements and the `go` directive in `go.mod`, and
download a newer toolchain to satisfy it. Deno always reads and writes `./deno.lock` beside the
manifest (`--lock=./deno.lock` overrides a `lock` key in `deno.json`). `deno update` receives names
without the `npm:` or `jsr:` scheme, so an `npm:x` and a `jsr:x` of the same name in one manifest
both move; the result is still checked against the lock file. A Cargo cooldown-fallback pin below a sibling's new minimum fails the `--precise` step: the
run ends `failed` with the reason `fallback-pin-rejected`; the manifest keeps its edit and the lock
file stays at its state from before the run.

**Lock file restore.** Before the first tool starts, `update` snapshots the lock files it may change
(Cargo: `Cargo.lock`; Go: `go.mod` and `go.sum`; npm, pnpm, Yarn and Bun: the
located lock file, plus every workspace `package.json` for Yarn; PyPI: the lock file; Bundler:
`Gemfile.lock`; Deno: `deno.lock`; Composer, Dart, NuGet, Gradle and Swift: their lock files). When the
regeneration fails, files whose bytes changed are written back and unchanged files are not touched.
If writing back fails, the report says `restore-failed` and names the file. After a timeout or an
interrupt the restore runs on unix only: on Windows a `.cmd` shim's child may still be writing after
the kill, so no restore is attempted. The manifest edit itself is not reverted outside `--open-pr`.

**Timeouts and signals (unix).** The whole regeneration shares a 5-minute budget. Each tool runs
in its own process group. On a timeout, on SIGINT or on SIGTERM deps-cli sends SIGTERM to the tool,
waits up to 2 seconds for it to exit, then sends SIGKILL to the whole group (also after the tool
itself exited, so a grandchild that ignored SIGTERM does not outlive the run). An interrupted run
prints the report with `lockfile: failed` (`kind: interrupted`) and exits `2`. The grace period lets
a tool run its own cleanup, but it does not make the lock file safe: `cargo` and `go` keep the
default SIGTERM disposition and can still leave a truncated lock file; the snapshot restore above
then puts the original bytes back. When deps-cli is in the foreground group
of its controlling terminal (an interactive run) the tool stays in that group instead, so `/dev/tty`
prompts keep working and Ctrl-C reaches it. Limits: in that foreground mode a timeout, or a SIGTERM
sent to deps-cli alone, signals only the direct child and grandchildren may survive; a SIGKILL of
deps-cli's own process group (`timeout -k`, `kill -9 -- -PGID`) does not reach a tool in its own
group; a `deps-cli ... &` job brought back with `fg` while `stty tostop` is set leaves the tool in
its own, background group, so its first terminal write stops it and the run waits for the 5-minute
timeout (exit `2`); the signal handlers are installed whenever a regeneration has pins to verify,
even for ecosystems where nothing is spawned, stay installed until exit, and override an inherited
`SIG_IGN` for SIGINT or SIGTERM; on Windows only the direct child is killed.

### Update groups (`[update.groups]`, `--group`)

```toml
[update.groups.minor-patch]
update_types = ["minor", "patch"]

[update.groups.tokio-stack]
dependencies = ["tokio", "tokio-util", "tracing"]
```

```bash
deps-cli update --config deps.toml --group minor-patch Cargo.toml
```

A group has four optional keys: `dependencies` (names, matched exactly after normalization),
`patterns` (name globs where `*` is the only wildcard, 1 to 214 bytes without whitespace),
`update_types` (`major`, `minor`, `patch`) and `dependency_type` (`production`, `development`,
`build`, `peer`, `optional`).

```toml
[update.groups.prod-serde]
patterns = ["serde*"]
dependency_type = "production"
```

A group without keys matches every update. An update is inside the group when its name is listed in
`dependencies` or matches a pattern (or both keys are absent), **and** its kind is listed (or
`update_types` is absent), **and** its role matches `dependency_type` (or that key is absent).
`production` means every role except development. An update whose kind cannot be classified is inside
only a group without `update_types`; a dependency whose role is unknown (for example an npm catalog
entry or override) is inside only a group without `dependency_type`. Group names are 1 to 64 characters of `a-z`, `0-9` and `-`, not starting or
ending with `-`; unknown keys are rejected.

`--group <name>` requires `--config` (groups are read only from an explicit config, like
`[update].ignore`), conflicts with `--security-only`, and exits `2` before any analysis when the
group is not defined. Every `applied` update outside the group is reported
`skipped (outside the selected --group)` and does not change the exit code. The group filter runs
after planning, so a dependency outside the group whose OSV latest-version check fails still aborts
the run (fail-closed). Groups are for splitting the update set into several runs, for instance one
for `minor-patch` and one for the rest.

### Opening a pull request (`--open-pr`)

```bash
deps-cli update --lockfile regenerate --open-pr github Cargo.toml
deps-cli update --lockfile regenerate --open-pr gitlab --config deps.toml --group minor-patch go.mod
```

`--open-pr github|gitlab` commits the manifest and lock file change of one run on a new branch,
pushes it to `origin` and opens a pull request with `gh` (GitHub) or a merge request with `glab`
(GitLab). It requires `--lockfile regenerate`, conflicts with `--dry-run` and `--offline`, and
supports the ecosystems whose lock file regeneration is implemented (Cargo, npm, pnpm, Yarn Berry,
Bun, Go, PyPI, Pipenv, Bundler, Deno, Composer, Dart, NuGet, Gradle, SwiftPM) plus those without a lock file
format (GitHub Actions, GitLab CI/CD, pre-commit, Maven). For Yarn Classic the analysis and
the manifest edit run first; the lock file regeneration is then refused (`unsupported`), the manifest
edit is restored from `HEAD`, the report is printed as a dry run and the run exits `2`. A workspace member whose lock file lies in the workspace root is allowed; a lock file outside
the repository root is refused (`lockfile-outside-repository`). A Go module with a `vendor` directory
requires that directory to be tracked in `HEAD`; otherwise the run exits `2` with
`--open-pr needs <path> to be tracked in git` before regeneration starts.

deps-cli never reads, logs or passes a token: `git`, `gh` and `glab` use their own credentials, and
every process runs without a shell, without stdin and with `GIT_TERMINAL_PROMPT=0` and
`GH_PROMPT_DISABLED=1`. A GitHub token needs `contents: write` and `pull-requests: write`; a GitLab
token needs `api` scope and push access. Pull requests created with the GitHub Actions
`GITHUB_TOKEN` do not trigger workflows (GitHub's rule). With several remotes, keep only `origin`
or run `gh repo set-default`. git 2.23 or newer is required (`git switch`, `git restore`).

The host CLIs are called with exactly these arguments (cwd = repository root):

```text
gh pr create --base=<base> --head=<branch> --title=<title> --body=<body>
glab mr create --source-branch=<branch> --target-branch=<base> --title=<title> --description=<body> --yes
```

Neither host CLI was run against a real host: both are covered by argv-recording shims, and the
`gh` flags were checked against `gh pr create --help` (2.103). The URL is the last non-empty line
the CLI prints, shown with control characters removed.

Before the manifest is read, `update` checks that the manifest is inside a git work tree, `HEAD` is
a named branch starting with neither `deps-cli/` nor `-`, a committer identity is configured and no tracked
file is modified (untracked files are fine and are never committed); otherwise it exits `2`.

The branch is `deps-cli/<ecosystem>/[<dir>/]<label>-<hash>`, where the label is the group name, the
`<name>-<version>` of a single update, or `all`. The hash covers the ecosystem, the manifest path,
the group and the exact update set, so the same update set always maps to the same branch and a
different one never shares it. Re-running while that branch exists on `origin` writes nothing,
prints `already proposed on <branch>` on stderr and reports the plan as a dry run, with the exit
code `update` computes for it. A local branch of that name that is not on `origin` exits `2`
before any write; delete it. A pull request closed without merging keeps its branch, and the same
update set is not proposed again until the branch is deleted. Superseded pull requests stay open
unless you pass `--close-superseded`.

Publishing first lists the tracked files that differ from `HEAD`. Only the manifest, the lock file a
`regenerated` outcome names (its real path, even when it lies above the manifest's directory) and the
companion files and directories it reports (Gradle's other lock files, the `gradle.lockfile` and
deleted legacy lock files of a layout migration, and a Go `vendor` tree, whose contents are not listed)
may differ: any other changed tracked file (an editor autosave,
a formatter, another tool running during the update) stops the run with exit `2` naming up to 10 of
them, with nothing committed or pushed. Otherwise the run creates the branch, stages exactly those
files and trees (an untracked or ignored lock file is never added), commits, pushes with upstream, creates
the request against the branch `HEAD` was on, prints its URL on stderr and only then switches back.
A Gradle layout migration is published whole: the created `gradle.lockfile` is staged and the deleted
legacy lock files are committed as deletions.

The title is `Bump <name> from <a> to <b>`, `Bump <n> dependencies in <manifest>` or
`Bump the <group> group with <n> updates in <manifest>`, at most 250 bytes; the body is a table of
at most 50 updates with every name and version rendered as code. A layout migration adds a
"Lock layout migration" section (the migrated files) and, when state was discarded, a "Dropped lock
state" section; each lists the first 10 entries, then "and N more". When nothing changed on disk it
prints `nothing to commit`.

If no item was settled (for example a `--security-only` run whose only fix stays
`requires-lockfile-update` because the regenerated lock file moved to a version not proven outside
the advisory ranges), no request is opened: the files are restored as below, the run prints
`no update was settled; no pull request opened (the manifest and the regenerated lock file were
reverted)`, renders the report as a dry run and exits with the
code `update` computes (`1` in practice).

If the lock file could not be regenerated (`failed`, `unsupported` or `skipped`), the tracked files
directly inside the manifest's directory, the tracked published lock files and companions, and the
published trees are restored to `HEAD` (including the index; a tree is also cleaned of untracked
files), the report is printed as a dry run and the run exits `2`; other edits are untouched, but an
edit made beside the manifest while the run was going is reverted too.

The manifest name is compared with git's spelling, so on a case-insensitive file system a manifest
given as `cargo.toml` for `Cargo.toml` is refused as an unexpected change (exit `2`, nothing
committed).

Each git, `gh` or `glab` step, including the commit and pre-push hooks it triggers, is limited to
2 minutes. SIGINT or SIGTERM in any phase stops every running process tree (SIGTERM, 2 seconds,
SIGKILL) and exits `2` naming the phase. After a failed or interrupted step the repository is left
as it was: a run interrupted while updating leaves the manifest edit (the next run refuses with a
dirty tree; `git restore <dir>`, plus the lock file in the workspace root for a member, the sibling
`package.json` files of a Yarn workspace, and `git clean -fd -- <vendor>` for new untracked files in a
Go `vendor` tree), and a failure after the branch switch leaves `HEAD` on the update
branch (`git switch <base>`, `git branch -D <branch>`). If the push may have happened, also delete
the remote branch with `git push origin --delete <branch>` (or, after a failed or interrupted
`gh pr create`, open the request by hand); otherwise the next run reports the branch as already
proposed and opens nothing. A failed switch-back after the request was created still exits `2`,
with the URL already printed.

| Situation | Exit code |
|---|---|
| Pull request opened, nothing to commit, no update proposed | as `update` (`0`, or `1` for a mixed run) |
| Already proposed | as `update` for the dry-run report |
| No update settled | as `update` for the dry-run report (`1` in practice) |
| Flag violation, preflight failure, untracked vendor tree, stale local branch, lock file not regenerated, unexpected changed file, publish set too large for one command line (`PublishSetTooLarge`, nothing staged), git/`gh`/`glab` failure or timeout, interrupt | `2` |

### Closing superseded requests (`--close-superseded`)

```bash
deps-cli update --lockfile regenerate --open-pr github --close-superseded Cargo.toml
```

After the new request is opened and its URL printed, `--close-superseded` closes your earlier
`deps-cli` requests that the new one replaces, with the comment `Superseded by <url>.`. It requires
`--open-pr`. Every request carries a hidden marker comment in its body describing the update set, so
a later run can match it. An earlier request is closed only when all six checks pass:

- it has the same author as the current `gh`/`glab` user;
- it is in the same repository;
- its branch starts with `deps-cli/<ecosystem>/`;
- it has exactly one commit;
- its marker has the same ecosystem, manifest, group and mode (`--security-only` or default);
- the new request covers every dependency of the old one at the same or a newer version.

A request that fails any check stays open, and its branch is never deleted. Closing never changes the
exit code: failures are printed as warnings. Cargo, npm, PyPI, Bundler, Dart, Composer and Deno
requests are compared by their requirement floors, and Go, Maven, Gradle, NuGet and Swift requests by
their ecosystem's own version ordering (a version pair the ordering cannot compare keeps the old
request open); GitHub Actions, GitLab CI and pre-commit are never closed, because their versions
cannot be ordered safely (this is decided before any `gh` or `glab` call and reported as a warning).
For GitHub each candidate is read with one `gh pr view` call; candidates are sorted oldest first and
at most 50 are read per run, and the report says whether the listing was complete, full or cut by
that cap. Requests opened without the marker are not closed. The checks catch extra
commits only: an edit of the request's title or body text is not detected. The `glab` calls of
this step have not been run against a real host.

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
| `1` | At least one item the run *wanted* to fix but could not — an unsafe/unrecognized span, `requires-lockfile-update`, `unfixable`, or a cooldown-fallback candidate that was itself OSV-flagged/unverified (also under a package manager's release-age window) |
| `2` | Execution error — a failed `--lockfile regenerate` step (report still printed), not a single recognized manifest, a registry required to classify the manifest was unreachable, a write/read failure, a symlinked manifest path (refused before any read, not just before the write), stale content detected before write, or `--security-only` combined with `network.offline`/vulnerability scanning disabled |

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

### `DEPS_OSV_BASE_URL`

An operator can point OSV lookups at a mirror or a local test double with the `DEPS_OSV_BASE_URL`
environment variable. It is a testing aid for the person running `deps-cli`; repository files cannot
set it. The value must be an absolute `https` URL (not a loopback, link-local or cloud-metadata
host) without userinfo, query or fragment, or an `http` URL to a loopback IP literal such as
`http://127.0.0.1:8080`. Plain `http` is allowed for that exact origin only, and redirects away from
the configured origin are not followed. A valid value prints one notice on stderr; an invalid value
prints the error and exits `2` in every subcommand, even with `--offline`.

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

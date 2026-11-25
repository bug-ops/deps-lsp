# Cargo

`deps-cargo` provides full LSP support for Rust's package manager.

## Basics

| | |
|---|---|
| Manifest file | `Cargo.toml` |
| Lock file (in-use version) | `Cargo.lock` (versions 3 and 4) |
| Registry | crates.io — sparse index (`index.crates.io`) for version lookups, REST API (`crates.io/api/v1`) for package-name search |
| Version syntax | Cargo's own requirement grammar (`semver::VersionReq`): `^`, `~`, `=`, `<`, `>`, `*`, and bare comparison operators |

`deps-cargo` parses every dependency-like table — `[dependencies]`, `[dev-dependencies]`,
`[build-dependencies]`, their `[target.<cfg-expr-or-triple>]` variants, and a workspace
root's `[workspace.dependencies]` — with byte-accurate position tracking, so hover,
diagnostics, completion, and code actions all anchor on the exact name/version/features span
in the file, not just the dependency's line.

```toml
[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }
```

Hovering `serde`'s version shows the latest crates.io release, whether the declared
requirement is satisfied, and a link to the crate's crates.io page; an outdated requirement
gets an inlay hint (`❌ 1.0.219`) and a matching diagnostic with a "Update to latest version"
code action. Typing inside the `features` array offers completion sourced from the latest
stable version's real feature list. `workspace = true` inheritance, `path =`/`git =`
dependencies, and a `package = "..."` rename (aliasing the TOML key to a different registry
lookup name) are all recognized and routed correctly — a renamed dependency's diagnostics and
completions key off the real crate name, not the local alias.

Update edits keep a partial requirement's precision: `~0.7` with a latest of 0.10.3 becomes
`~0.10`, a bare `0.7` becomes `0.10`, and `^0.4` with a latest of 1.0.19 becomes `1.0` (a
redundant `^` is dropped), not the full version. A prerelease pick, an all-zero requirement
(`0`, `^0.0`) and a security-fix or cooldown-fallback target write the full version.

## Custom/Private Registries

A Cargo dependency declared as `registry = "<alias>"` or `registry-index = "<url>"`
resolves against that registry's own sparse index — hover, diagnostics, completion,
and code actions all work against it exactly as they do for a plain crates.io
dependency, instead of showing no version data at all.

**Resolution**: `registry = "<alias>"` is resolved by reading `[registries.<alias>]`
from the same `.cargo/config.toml` hierarchy Cargo itself consults — every
ancestor directory's `.cargo/config.toml` between the opened manifest and the
filesystem root, closest directory winning — plus `$CARGO_HOME/config.toml` as the
lowest-precedence tier. `registry-index = "<url>"` needs no config lookup: it is
already a concrete index URL. Only `sparse+https://` (or a bare `https://`) index
URLs are supported; `http://` and any URL carrying `user:pass@` are rejected.
Cargo's `CARGO_REGISTRIES_<NAME>_INDEX`/`_TOKEN` environment variable overrides are
also honored.

**Authentication**: a registry token is bound to the registry URL declared in
`$CARGO_HOME/config.toml` (or by its own `CARGO_REGISTRIES_<NAME>_INDEX`/`_TOKEN` environment
variables) and is sent to that URL only. A registry alias resolved from a workspace
`.cargo/config.toml` — a file a cloned, untrusted repository fully controls — never
gets a credential attached just because an identically-named alias is configured with
one in `$CARGO_HOME`: the alias name carries nothing. This is deliberate: it prevents a hostile
repository from redirecting a familiar alias name (e.g. `"github"`) to an attacker-controlled host
and harvesting whatever token the user's real, differently-scoped registry of that
name would have used. A repository entry that names *the same URL* as your registry (an alias, a
`registry-index`, or a `[source]` replace-with target) does get your token for that URL, and only
for that URL, so which entry registers first never matters.

The token is sent verbatim in the `Authorization` header, with no `Bearer` prefix, exactly as
Cargo itself sends it.

**Mirroring crates.io (`[source]` replace-with)**: a workspace's
`[source.crates-io] replace-with = "<name>"` chain, terminating at a
`[source.<name>] registry = "sparse+https://…"` entry, reroutes every plain
(un-aliased) dependency to that mirror — hover/diagnostics/completion reflect the
mirror's data, the crates.io hover link stays intact (Cargo verifies per-version
checksum equality against crates.io for a mirror, so its content is exactly as
trustworthy as crates.io's own), and OSV vulnerability scanning still runs against
it. A chain terminating at a `directory` (vendored), `local-registry`, or
git-index (non-sparse) source instead leaves plain dependencies resolving against
crates.io unchanged — vendoring/mirroring through those mechanisms doesn't
guarantee the same version *set* as crates.io, so degrading to no data would be
worse than the pre-existing crates.io answer.

**Reachability policy (`registries.workspace_registries`, security)**: a
workspace-declared registry index (the `registry`/`registry-index` alias path, or a
`[source]` mirror) is checked against this setting before it is ever fetched — a
hostile cloned repository can write both, and this LSP parses on file open, before
any build runs. This setting is shared with npm's `.npmrc` resolution, PyPI's
custom-index resolution, NuGet's `NuGet.Config` resolution, Go's `GOPROXY`
chain, and GitLab CI/CD's self-hosted-instance resolution — one process-wide
`HttpCache` policy governs every ecosystem's workspace-declared registry fetches;
see [npm](npm.md#customprivate-registries),
[PyPI](pypi.md#customprivate-indexes),
[NuGet](nuget.md#privatecustom-feeds),
[Go](go.md#goproxygoprivate-support), and
[GitLab CI/CD](gitlab-ci.md#self-hosted-instances) for what
that sharing means in practice. Three values:

| Value | Behavior |
|-------|----------|
| `"public_only"` (default) | Only a publicly-routable host is fetched — blocks loopback, link-local, RFC1918/CGNAT, unique-local-v6, and cloud-metadata-range hosts (e.g. `169.254.169.254`) declared by a workspace file. A corporate `https://index.mycorp.dev`-style registry still works, since a DNS name cannot be classified as internal without resolving it — see the residual-risk note below. |
| `"off"` | No workspace-declared index is ever fetched — the only complete boundary. Applies to the alias path as well as `[source]`. |
| `"all"` | Public hosts plus the private hosts and CIDR ranges listed in the `DEPS_LSP_PRIVATE_REGISTRY_HOSTS` environment variable (see [Configuration](../configuration.md#private-registry-allowlist)) — the escape hatch for a workspace that legitimately points at an RFC1918 registry. Without that variable it behaves like `"public_only"`: the setting is repository-controllable, so the variable is the effective control, and a listed host is reachable on any port. It never allows loopback, link-local, cloud-metadata, unspecified or reserved addresses, which are refused under every value. |

**Proxies.** A workspace-declared registry connects directly and bypasses the system proxy by
default, so the connect-time check sees the real address; see
[Proxies and guarded registry traffic](../configuration.md#proxies-and-guarded-registry-traffic)
for the opt-in variable.

**Hosts that resolve to a blocked address.** The check above looks at the declared host name. A
name that resolves, when the connection is made, to a blocked address class (for example a public
name that points at `10.0.0.5`) is refused too, in every ecosystem, and the dependency shows a
policy-specific message instead of a generic fetch failure. The message names the address class
only, never the address. For the classes `"all"` does not allow, it says the host "is never a
registry under any policy"; for the others it says the host is "blocked by
registries.workspace_registries policy" and adds that private hosts need `"all"` and
`DEPS_LSP_PRIVATE_REGISTRY_HOSTS`. Cached data for a registry is still served while
revalidation is blocked, since no connection is made.

Registries your `$CARGO_HOME/config.toml` (or `CARGO_REGISTRIES_<NAME>_INDEX`) declares, and
any workspace alias naming the same URL, are **never** policy-checked, under any of the three
values — that file is the user's own trusted configuration, not something a cloned repository
controls. The never-a-registry floor still applies: such a registry on a loopback or link-local
host is rejected. A blocked index is never silent: it is
logged, and a `registry`/`registry-index` dependency line additionally gets an
informational diagnostic naming the blocked host class (a `[source]`-chain block is
log-only, since it is a property of `.cargo/config.toml`, not of any one
dependency line). This diagnostic is not Cargo-specific (issue #925): npm's
`.npmrc` `registry=`/`@scope:registry=` resolution, PyPI's `--index-url`/Poetry
`source =`/uv `index =` resolution, and NuGet's `NuGet.Config`
`<packageSources>`/`<packageSourceMapping>` resolution all surface the same
informational diagnostic on the affected dependency's own line when a declared
registry is blocked, instead of degrading silently to the public registry. Go's
`GOPROXY` chain and GitLab CI/CD's `registries.gitlab_instance_host`/`component:`
host resolution were the last two ecosystems to close this gap
(issues #967, #968) — every ecosystem with a workspace-declared, policy-gated
registry host now surfaces the same kind of diagnostic instead of leaving the
block visible only in the server log.

Beyond that initial URL-string check, `public_only` (and `off`/`all`) is also
enforced at **connect time**: the address a workspace-declared index's hostname
actually resolves to, and the target of any redirect hop the fetch follows, are
both checked against the setting too — not just the declared URL string at parse
time. This closes a DNS-rebinding gap (issue #455) where a workspace file declares
a host that classifies as public at parse time (`https://evil.example/`) but
resolves to a blocked address (an RFC1918/CGNAT range, or one rebound after parse
time) at actual fetch time.

Tightening the setting (e.g. `all` -> `public_only`/`off`) now takes effect on
already-open documents immediately: `workspace/didChangeConfiguration` re-parses
every open document whose ecosystem consults this policy and forces a full
version refetch, purging any cached version obtained through the now-untrusted
registry rather than requiring the document to be edited or reopened first
(issue #592).

**Known limitations**:
- Editing `.cargo/config.toml` re-parses and re-fetches the open manifests it affects (it is a
  watched file).
- The sparse index protocol has no search endpoint, so package-*name* completion
  (typing a brand-new dependency) always searches crates.io, even inside a
  workspace whose default registry is mirrored elsewhere.
- Git-index (non-sparse) private registries remain unsupported, matching prior
  behavior.

## Cargo's Publish-Age Window (`min-publish-age`)

Cargo can refuse releases younger than a configured age. deps-lsp reads the same settings from
the repository's `.cargo/config.toml` files and **explains** the hold. It never writes the held
version (except as a security fix) and moves you to the newest eligible one instead, as described
in [Release-Age Holds](../cross-ecosystem/version-diagnostics.md#release-age-holds).

```toml
# .cargo/config.toml
[registry]
global-min-publish-age = "7 days"     # every registry

[registries.crates-io]
min-publish-age = "2 weeks"           # wins over the global key for crates.io

[resolver]
incompatible-publish-age = "allow"    # "allow" turns the window off
```

Values use Cargo's grammar: `<integer> <unit>` with `second`, `minute`, `hour`, `day`, `week` or
`month` (a month is 2 629 746 seconds), singular or plural. `0` disables the window at that key.
A malformed value is ignored with one logged warning per config file. A window above ten years is
clamped.

**While `latest` is inside the window:**

- The *outdated* diagnostic names the newest eligible version and why `latest` is held, for
  example `(3.9.0 excluded by cargo registry.global-min-publish-age = 7 days; eligible in 4 days)`.
  There is no diagnostic when there is nothing newer to move to.
- Hover keeps the true `Latest` line and adds a "Held back" callout naming the setting.
- `deps-cli update` writes the eligible version, or reports `within-native-cooldown` (exit 0) when
  there is none.
- A vulnerability fix is **never** moved by the window: the quick fix title notes
  `inside <setting>` when the target is still younger than the window.

See [Release-Age Holds](../cross-ecosystem/version-diagnostics.md#release-age-holds) for inlay
hints, the lens and code actions.

**Which versions stay eligible:** a version with no known publish time, one published at least
the window ago (the boundary is exclusive), and any version that appears in `Cargo.lock` for that
package (including a transitive duplicate). The lock is read when you ask, so a `Cargo.lock`
change lifts the hold immediately, and a release published after the last fetch is judged on the
live version list the hover and code actions use.

**Scope and limits:**

- Only the repository's own config is read: `.cargo/config.toml` from the manifest directory up
  to the workspace root (the manifest directory alone when there is no workspace root). A config
  in a parent of the workspace root, your `~/.cargo/config.toml`, `$CARGO_HOME/config.toml` and
  `CARGO_*` environment variables are **ignored**, so an opened repository cannot be influenced
  by files outside it and your own settings are not guessed at.
- A `registry-index` URL dependency gets only the global key (it has no name to key on). Git and
  path dependencies have no window.
- The diagnostic and the code lens read the last fetched version list while hover and code
  actions read a fresh one, so right after a new release they can briefly name different versions.
- A same-version git or path lock entry also keeps the registry release eligible (the lock maps
  do not record sources).
- A malformed value is ignored (with one warning per config file naming the file, the count and
  the first keys) and the next valid value in a farther file applies; Cargo itself would reject
  the config. A malformed `resolver.incompatible-publish-age` reads as the `deny` default.
- Set `freshness.honor_native_cooldown` to `false` to ignore the window entirely; it works
  independently of `freshness.enabled`. The keys are still parsed as part of the shared
  `.cargo/config.toml` reading; only the window and its warnings are switched off.

# Cargo

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

**Authentication**: a bearer token is attached to requests against a registry
resolved from `$CARGO_HOME/config.toml` (or its own `CARGO_REGISTRIES_<NAME>_TOKEN`
environment variable) only. A registry alias resolved from a workspace
`.cargo/config.toml` — a file a cloned, untrusted repository fully controls — never
gets a credential attached, even if an identically-named alias is configured with
one in `$CARGO_HOME`. This is deliberate: it prevents a hostile repository from
redirecting a familiar alias name (e.g. `"github"`) to an attacker-controlled host
and harvesting whatever token the user's real, differently-scoped registry of that
name would have used.

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
| `"all"` | Every workspace-declared index is fetched, matching this LSP's behavior before this setting existed — the escape hatch for a workspace that legitimately points at an RFC1918/loopback registry. |

`$CARGO_HOME/config.toml`-configured registries are **never** policy-checked, under
any of the three values — that file is the user's own trusted configuration, not
something a cloned repository controls. A blocked index is never silent: it is
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
- Editing `.cargo/config.toml` does not take effect until the affected `Cargo.toml`
  is next reparsed (edited, or the document reopened) — there is no dedicated file
  watcher for it yet.
- The sparse index protocol has no search endpoint, so package-*name* completion
  (typing a brand-new dependency) always searches crates.io, even inside a
  workspace whose default registry is mirrored elsewhere.
- Git-index (non-sparse) private registries remain unsupported, matching prior
  behavior.

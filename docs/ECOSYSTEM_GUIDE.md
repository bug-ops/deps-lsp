# Ecosystem Implementation Guide

This guide explains how to add support for a new package ecosystem (e.g., Go modules, Maven, Gradle) to deps-lsp.

## Supported Ecosystems

deps-lsp provides comprehensive LSP support for 13 package ecosystems:

| Ecosystem | Language | Manifest File(s) | Lock File(s) | Features |
|-----------|----------|-----------------|--------------|----------|
| **Cargo** | Rust | `Cargo.toml` | `Cargo.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens, feature flag completion, alternate/private registry resolution via `.cargo/config.toml` (see below) |
| **npm** | JavaScript/TypeScript | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Hover, inlay hints, completion, code actions, diagnostics, code lens, custom/private registry resolution via `.npmrc` (see below) |
| **PyPI** | Python | `pyproject.toml`, `requirements.txt`, `constraints.txt` (also recognized under a `requirements/` directory, e.g. `requirements/base.txt`) | `poetry.lock`, `uv.lock` | Hover with PEP 508 environment marker display ("Active when: `<marker>`"), inlay hints, completion, code actions, diagnostics, code lens, document links for `-r`/`-c`/`--requirement`/`--constraint` file references, private/custom index resolution via `--index-url`/`--extra-index-url`, Poetry `[[tool.poetry.source]]`, and uv `[tool.uv.index]`/`[tool.uv.sources]` (see below) |
| **Go** | Go | `go.mod` | `go.sum` | Hover, inlay hints, completion, code actions, diagnostics, code lens, pseudo-version support, `$GOENV` `GOPROXY`/`GOPRIVATE` proxy-chain resolution (see below) |
| **Bundler** | Ruby | `Gemfile` | `Gemfile.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens |
| **Dart** | Dart | `pubspec.yaml` | `pubspec.lock` | Hover with corrected version ordering (prereleases sort below base release — see below), inlay hints, completion, code actions, diagnostics, code lens |
| **Maven** | Java | `pom.xml` | `maven-metadata.xml` (CDN) | Hover with corrected version ordering (numeric segments outrank qualifiers, prereleases sort below base release), inlay hints, completion, code actions, diagnostics, code lens (property-versioned dependencies not covered — see below) |
| **Gradle** | Kotlin/Groovy | `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml` | — | Hover with corrected version ordering (same as Maven), inlay hints, completion, code actions, diagnostics, code lens (variable/catalog-versioned dependencies not covered — see below), variable resolution (`gradle.properties`) |
| **Composer** | PHP | `composer.json` | `composer.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens (requirement matching and "latest version" selection both use corrected stability-qualifier ordering — see below) |
| **Swift** | Swift | `Package.swift` | `Package.resolved` | Hover, inlay hints, completion, code actions, diagnostics, code lens (range-form dependencies not covered — see below), GitHub API support |
| **NuGet** | .NET | `.csproj`, `.fsproj`, `.vbproj`, `Directory.Packages.props`, `packages.config` | `packages.lock.json`, `packages.<project>.lock.json` (multi-project) | Hover, inlay hints, completion, code actions, diagnostics, code lens, central package management support, SemVer2 prerelease handling, hover-only unlisted-version marker, private/custom feed resolution via `NuGet.Config` (see below) |
| **Deno** | JavaScript/TypeScript (Deno runtime) | `deno.json`, `deno.jsonc` | — (no `deno.lock` support yet) | Hover, inlay hints, completion, code actions, diagnostics, code lens — `jsr:` specifiers via the keyless JSR API, `npm:` specifiers delegate to the same registry client `npm` uses; `imports` map only, `scopes`/`importMap` not covered — see below |
| **GitHub Actions** | YAML | `.github/workflows/*.yml`, `*.yaml` | — (no lock file) | Hover, inlay hints, code actions, diagnostics, code lens (package-name completion not covered — see below); tag/commit-SHA/branch `uses:` pins via the GitHub tags API; reusable-workflow calls recognized but not version-resolved — see below; release-age hint and cooldown diagnostic require `GITHUB_TOKEN` — see below |

### Cargo Custom/Private Registries

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
custom-index resolution, and NuGet's `NuGet.Config` resolution below (one
process-wide `HttpCache` policy governs every ecosystem's workspace-declared
registry fetches — see
[npm Custom/Private Registries](#npm-customprivate-registries),
[PyPI Custom/Private Indexes](#pypi-customprivate-indexes), and
[NuGet Private/Custom Feeds](#nuget-privatecustom-feeds) for what that sharing
means in practice). Three values:

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
dependency line).

Beyond that initial URL-string check, `public_only` (and `off`/`all`) is also
enforced at **connect time**: the address a workspace-declared index's hostname
actually resolves to, and the target of any redirect hop the fetch follows, are
both checked against the setting too — not just the declared URL string at parse
time. This closes a DNS-rebinding gap (issue #455) where a workspace file declares
a host that classifies as public at parse time (`https://evil.example/`) but
resolves to a blocked address (an RFC1918/CGNAT range, or one rebound after parse
time) at actual fetch time.

*Residual risk*: tightening the setting (e.g. `all` -> `public_only`/`off`) only
gates *future* parses. An alternate-registry client already registered while the
policy was looser stays reachable after the tightening, because
`workspace/didChangeConfiguration` does not re-parse already-open documents, so
the registry client that URL produced is never purged. It goes away only once
its owning document is next re-parsed (edited, or reopened).

**Known limitations**:
- Editing `.cargo/config.toml` does not take effect until the affected `Cargo.toml`
  is next reparsed (edited, or the document reopened) — there is no dedicated file
  watcher for it yet.
- The sparse index protocol has no search endpoint, so package-*name* completion
  (typing a brand-new dependency) always searches crates.io, even inside a
  workspace whose default registry is mirrored elsewhere.
- Git-index (non-sparse) private registries remain unsupported, matching prior
  behavior.

### npm Custom/Private Registries

An npm dependency whose scope (via `@scope:registry=`) or whose workspace (via a
top-level `registry=` override) resolves to a private/custom registry through
`.npmrc` gets the same hover/diagnostic/completion value a `registry.npmjs.org`
dependency gets — instead of showing no version data, or (before this feature)
silently checking the wrong (public) registry.

**Resolution**: `.npmrc` is read from a two-tier hierarchy — the project tier
(walked from the opened `package.json`'s directory up to the filesystem root,
closest directory winning; a deliberate superset of npm's own project-root-only
read, chosen for monorepo ergonomics and mirroring Cargo's `.cargo/config.toml`
discovery) and the user tier (`~/.npmrc`). The global tier
(`$PREFIX/etc/npmrc`) is not read. A `@scope:registry=` entry always takes
precedence over a top-level `registry=` override for a dependency in that scope.
Scope keys are matched byte-exact, with no case folding, matching npm's own
lookup. A `${VAR}`-style placeholder in either key's value is expanded from this
LSP server's own process environment; an undefined variable makes the whole entry
invalid (same outcome as an invalid URL, below).

**Authentication**: phase 1 carries **no** authentication at all. `_authToken`,
`_auth`, `_password`, `_authIdent`, `always-auth`, and every `//<host>/:_*`
scoped-credential key are never parsed, held in memory, logged, or transmitted —
every alternate-registry request is unauthenticated. A follow-up spec is required
before any credential is wired up.

**Fail-closed on misconfiguration**: a `registry=`/`@scope:registry=` value that
is not a well-formed `https://` URL, carries userinfo, or is blocked by the
reachability policy below shows no version data for the affected dependency —
never a silent fallback to `registry.npmjs.org`, matching Cargo's equivalent
guarantee for a misconfigured registry alias.

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented above — unlike Cargo's `$CARGO_HOME`-is-trusted split, npm's
project and user `.npmrc` tiers are policy-*symmetric*: phase 1 has no credential
provenance to protect, so there is no tier that is "the user's own configuration"
in the way `$CARGO_HOME` is for Cargo. Setting `registries.workspace_registries`
to `"all"` for npm's benefit also widens it for Cargo, and vice versa — see the
setting's own doc above.

**Known limitations**:
- Editing `.npmrc` does not take effect until the affected `package.json` is next
  reparsed (edited, or the document reopened) — there is no dedicated file
  watcher for it yet.
- Package-*name* completion (typing a brand-new dependency) always searches
  `registry.npmjs.org`, even for a scope resolved to a private registry — the
  string being searched is a prefix the user typed into the name field, not a
  resolved private dependency name, so this is safe but not registry-aware.
- A dependency resolved to a private registry drops out of OSV vulnerability
  scanning and loses its npmjs.com hover link (an advisory or link keyed to the
  public package name does not apply to a same-named private package) and its
  relative-age ("published N days ago") hover suffix.
- `.yarnrc`/`.yarnrc.yml` (Yarn Berry's own config format) and pnpm-specific
  extensions to `.npmrc` are not read; a standard `.npmrc` present in the
  workspace is still honored either way.

### PyPI Custom/Private Indexes

A PyPI/pip dependency whose applicable index is overridden via `requirements.txt`
`--index-url`/`--extra-index-url`, Poetry's `[[tool.poetry.source]]`, or uv's
`[tool.uv.index]`/`[tool.uv.sources]` gets the same hover/diagnostic/completion
value a plain `pypi.org` dependency gets — instead of showing no version data, or
(before this feature) silently checking the wrong (public) index.

**Resolution order — the security-relevant rule**: whether an explicit
`--index-url` (or Poetry `primary`/`default`-priority source, or a uv index with
`default = true`) is present in the file determines the order every plain
dependency is checked in:

- **An explicit primary is declared**: that index is checked first, then every
  `--extra-index-url`/supplemental source, in declaration order. No implicit
  `pypi.org` hop is appended — `--index-url` *replaces* the default index (matching
  pip's own semantics), so a file that wants `pypi.org` reachable alongside an
  explicit primary must list it as an extra itself.
- **No explicit primary, but extras exist**: declared extras are checked *before*
  the implicit `pypi.org` fallback, which is always checked last. This is
  deliberately the reverse of what might seem intuitive, and is the whole point of
  this feature's design: it stops a private-only package's name from ever being
  sent to `pypi.org` before the user's own declared index has had a chance, and
  stops a same-named public package from silently shadowing a private one the user
  explicitly configured (the "dependency confusion" attack shape). This diverges
  from pip's own resolver, which pip's docs describe as having no defined
  precedence between `--index-url` and `--extra-index-url` and explicitly warn is
  unsafe for private packages for exactly this reason.

uv's `default = true` index follows this same "no explicit primary" shape: it is
uv's own lowest-priority, last-resort index — checked *after* every other declared
uv index, replacing the implicit `pypi.org` slot, never checked first the way an
explicit `--index-url` primary is.

**Poetry named sources**: a dependency declaring `source = "<name>"` (Poetry) or a
`[tool.uv.sources] <dep> = { index = "<name>" }` binding (uv) resolves directly
against that one named source, with no fallback to any other index — a deliberate,
single-hop route. A Poetry source with no `priority` key is treated as `primary`
(matching current Poetry documentation); `explicit`-priority Poetry sources and
`explicit = true` uv indexes are reachable only by name, never auto-included in the
extras chain.

**Authentication**: phase 1 carries **no** authentication at all — the same
Cargo/npm precedent. Any index URL with embedded userinfo (`https://user:pass@…`)
is rejected outright rather than stripped-and-used; `keyring`/`.netrc` are not
detected or acknowledged. This means an auth-gated private feed (e.g. Azure
Artifacts) is not reachable end-to-end until a follow-up auth spec ships — the
routing/fallback mechanism itself still works correctly for any unauthenticated
private index (an internal mirror behind network-level access control, or a devpi
instance with anonymous read).

**Fail-closed on misconfiguration**: an explicit `--index-url`, Poetry
primary/named source, or uv `default`/named index that fails validation (not
`https`, malformed, or blocked by the reachability policy below) shows no version
data for every affected dependency — never a silent fallback to `pypi.org`. An
invalid `--extra-index-url`/supplemental/non-default entry, by contrast, is simply
dropped from the fallback chain (with a logged warning) rather than failing the
whole dependency closed, since an extra is additive/optional by definition — the
remaining valid hops (including the implicit `pypi.org` fallback, if applicable)
still serve the dependency.

**Availability trade-off of the security fix above**: a genuine transport error
(timeout, 5xx, connection refused) on any hop — including a declared extra that
happens to be hop 0 in the no-explicit-primary case — halts resolution for that
dependency rather than silently falling through to the next hop. Applied to a file
with only `--extra-index-url` entries, an unreachable extra (a developer off the
corporate VPN, say) means every dependency in that file loses its version data,
including ordinary public ones with no relation to the private index. This is
intentional, not a bug: falling through on a transport failure would send every
affected package's name to `pypi.org` precisely when the private index is merely
unreachable — the same disclosure the resolution-order rule above exists to
prevent. A distinguishable log message ("extra index unreachable — resolution
halted, not falling back to pypi.org") accompanies this case so it can be told
apart from a genuinely missing package.

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented above for Cargo/npm — the same `"public_only"`/`"off"`/`"all"`
values, the same shared process-wide `HttpCache` policy. Only *explicitly-declared*
indexes (a primary, every extra, every named source) are gated; the implicit
`pypi.org` fallback used by the no-explicit-primary case is never itself subject
to this setting, since it is the same public-tier client every plain dependency
already uses. What this means in practice depends on whether the file declares an
explicit `--index-url` primary:

- **No explicit primary, extras only**: `workspace_registries = "off"` blocks
  every declared extra, and — since there is no implicit-fallback slot to lose —
  every plain dependency in the file degrades gracefully to resolving against
  `pypi.org` directly, exactly as if the file declared nothing at all.
- **An explicit `--index-url` primary**: an explicit primary *replaces* the
  default index rather than adding to it (FR-005(a)), so there is no implicit
  `pypi.org` hop to fall back to. If `off` blocks that primary, it fails closed
  (`CustomRegistry`, FR-006) and **every** dependency in the file loses version
  data — `off` does not silently degrade to public resolution here, unlike the
  extras-only case above.

**Known limitations**:
- Editing a file's index declarations does not take effect until it is next
  reparsed (edited, or the document reopened) — there is no dedicated file watcher
  for it yet.
- `pip.conf`/`pip.ini` and `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL` environment
  variables are not read at all — a project relying solely on those (rather than
  in-file `--index-url` flags) sees no improvement from this feature.
- `-r`/`-c` include propagation is not implemented: a file included via `-r
  base.txt` does not inherit the includer's index declarations, and vice versa.
- A `[tool.uv.sources]` binding is only recognized for the `index = "<name>"`
  shape — `git =`, `path =`, and `workspace = true` bindings are a distinct
  concept (dependency provenance, not registry routing) and are not read.
- **Cosmetic limitation**: a plain dependency in an extras-only file is classified
  as resolved via the alternate-index chain at parse time, before the winning hop
  is actually known — if it ends up resolving via the implicit `pypi.org`
  fallback, its hover heading still omits the `pypi.org` project link (the same
  suppression a genuinely private dependency gets). No data-correctness impact.

### Go GOPROXY/GOPRIVATE Support

A Go module dependency whose applicable proxy is overridden via a `$GOENV`
`GOPROXY=` entry, or whose module path matches a `$GOENV` `GOPRIVATE=` glob
pattern, gets the same hover/diagnostic/completion value a
`proxy.golang.org`-resolved dependency gets — instead of showing no version
data, or (before this feature) silently checking the wrong (public) proxy.

**Resolution**: `$GOENV` is read once per process — the `GOENV` environment
variable if set and non-empty, else the platform default
`os.UserConfigDir()/go/env` (`~/.config/go/env` on Linux/macOS,
`%AppData%\go\env` on Windows), matching `go env -w`'s own file. `GOPROXY` is
parsed as a comma-or-pipe-separated ordered chain of hops (`go help goproxy`
semantics), recognizing the `direct` and `off` sentinels; when absent, the
existing hardcoded `https://proxy.golang.org` default applies unchanged.
`GOPRIVATE` is a comma-separated list of `path.Match`-style glob patterns
(`go help goprivate`) matched against a module's full path — a matching
module bypasses the entire `GOPROXY` chain and routes straight to the
`direct` terminal hop, regardless of what `GOPROXY` is configured to.

**`direct`/`off` show no data (phase 1 limitation)**: `deps-go` has no
direct-VCS resolution mechanism (no `go-import` meta-tag discovery, no
arbitrary-VCS client), so both the `direct` sentinel and `off` are
implemented as fail-closed terminal hops — the chain-fallback mechanics are
correct (a proxy hop's explicit not-found response falls through to the
next hop, including `direct`/`off`), but neither sentinel itself produces
version data. This preserves `GOPRIVATE`'s confidentiality guarantee (a
private module path is never sent to any proxy hop) even though no
replacement data is shown yet.

**Authentication**: phase 1 carries **no** authentication at all — the same
Cargo/npm/PyPI precedent. A `GOPROXY` hop URL with embedded userinfo
(`https://user:pass@…`) is rejected outright rather than stripped-and-used;
`.netrc` and a bare local-filesystem-path hop are not detected or
acknowledged.

**Fail-closed on misconfiguration**: a `GOPROXY` hop that fails validation
(not `https`, malformed, or blocked by the reachability policy below) is
dropped from the chain (with a logged warning) when other valid hops
remain; if every hop turns out invalid, the whole chain fails closed
(no version data for any affected dependency) — never a silent fallback to
`proxy.golang.org`. A transport failure (timeout, 5xx, connection refused)
on any hop halts resolution for that dependency rather than silently
falling through to the next hop, mirroring PyPI's identical trade-off (see
above) for the same reason: falling through would risk resolving a private
module through a fallback the reachability state does not actually support.

**`,` vs `|` separator semantics**: the two `GOPROXY` separators are not
interchangeable — each governs a different fallback trigger for the hop
transition it precedes, matching `go help goproxy`/`modfetch/proxy.go`:
- `,` falls through to the next hop **only on an explicit not-found
  response** (`404`/`410`) — a transport failure (timeout, 5xx, connection
  refused) on that hop halts resolution for the dependency instead (see
  above).
- `|` falls through to the next hop on **any** error from that hop,
  including a transport failure.

A single `GOPROXY` value may mix both (e.g.
`GOPROXY=https://a.example|https://b.example,direct`); each transition
between two consecutive, *valid* hops keeps the separator that preceded
it, so a chain can combine "skip on any failure" and "skip only when
genuinely absent" hop-to-hop as needed.

**Known limitation**: when an invalid hop is dropped (per the fail-closed
rule above) between two surviving hops, only the separator immediately
preceding the surviving hop is kept — a separator that preceded the
*dropped* entry is discarded rather than carried over. For example,
`GOPROXY=https://a.example|not-a-valid-url,https://c.example` records the
`,` after the dropped entry, not the `|` the user actually wrote before
it, so a "skip on any failure" the user intended for the `a` -> `c`
fallback can be silently narrowed to "skip only when not found" whenever
the hop in between happens to be invalid. Pinned by a test rather than
fixed here — see issue #559's follow-up tracking for the underlying
separator-carryover fix.

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented above for Cargo/npm/PyPI. The default public chain
(`https://proxy.golang.org,direct`) used when `$GOENV` declares no
`GOPROXY` override is never subject to this gate — it is the same
ungated public-tier client `deps-go` already uses today.

**Known limitations**:
- Editing `$GOENV` does not take effect until the affected `go.mod` is next
  reparsed (edited, or the document reopened) — there is no dedicated file
  watcher for it yet.
- Live `GOPROXY`/`GOPRIVATE`/`GONOSUMCHECK`/`GOFLAGS` process environment
  variables (as opposed to the `$GOENV` file) are not read.
- `GOSUMDB`/`GONOSUMCHECK` checksum-database verification is out of scope
  entirely — no ecosystem crate in this project performs integrity
  verification today.
- Package-*name* completion is unconditionally a no-op for a dependency
  resolved to a non-default `GOPROXY` chain or a `GOPRIVATE`-routed
  module — Go has no package-name search endpoint in its module-proxy
  protocol at all.

### NuGet Private/Custom Feeds

A NuGet dependency whose applicable feed is overridden via a repository's
`NuGet.Config` `<packageSources>` (Azure Artifacts, GitHub Packages, an internal
Artifactory/BaGet/ProGet instance) gets the same hover/diagnostic/completion
value a plain `api.nuget.org` dependency gets, instead of always querying the
public feed regardless of what the project actually configures.

**Discovery — every in-repo ancestor file, merged root-to-leaf**: `deps-nuget`
walks upward from the manifest's directory toward the filesystem root (capped at
64 directories), checking `NuGet.Config`/`nuget.config`/`NuGet.config` at each
level, and merges **every** file it finds — not just the nearest one — applying
them in root-to-leaf order. A `<clear/>` anywhere in that chain is sticky for
every file below it: a repo-root `NuGet.Config` with `<clear/>` plus a private
feed stays cleared even for a subproject whose own `NuGet.Config` adds a second
feed without repeating `<clear/>`. User-profile and machine-wide config
(`%APPDATA%\NuGet\NuGet.Config`, `~/.nuget/NuGet/NuGet.Config`) are not read —
deliberately: that is exactly where `<packageSourceCredentials>` most commonly
lives, and a global `<clear/>` there would silently re-route every project on
the machine.

**Additive by default**: a `NuGet.Config` with no `<clear/>` adds its declared
sources alongside the implicit `api.nuget.org` source, matching `nuget.exe`'s
own default-source-preservation behavior — a package present only on the new
feed and a package present only on `api.nuget.org` both keep resolving
correctly.

**`<packageSourceMapping>` (dependency-confusion defense) takes priority when
present**: NuGet 6.0+'s recommended `<packageSourceMapping>` element
(`<packageSource key="..."><package pattern="..." /></packageSource>`) is
honored when declared with at least one pattern — every dependency is then
routed by pattern match (bare `*`, a trailing-`*` prefix glob, or an exact id;
longest/most-specific match wins, exact beats prefix, ties make every tied
source eligible) instead of the additive chain above. A package matching no
pattern shows no version data (real NuGet fails restore with `NU1100` in this
case) rather than falling through to an unmapped feed — this is what actually
closes the dependency-confusion attack `<packageSourceMapping>` exists for:
without honoring it, an internal package name could still be looked up against
`api.nuget.org` on a cache miss. `<packageSourceMapping>` rules are merged
across the same root-to-leaf ancestor chain as `<packageSources>` — a broader
ancestor mapping rule is never silently dropped by a narrower leaf file's own
mapping (a leaf-level `<clear/>` inside `<packageSourceMapping>` itself is not
honored — see Known Limitations below). A mapping key that is the literal
`nuget.org` and names no declared `<packageSources>` entry resolves to the
real public feed rather than failing closed — the common real-world shape,
since `nuget.org` itself typically lives in the machine/user-profile config
this feature does not read.

**`<disabledPackageSources>`/`<packageSourceCredentials>`/`<remove>` are
respected**: a source disabled via `<disabledPackageSources><add key="..."
value="true" />`, removed via `<packageSources><remove key="..."/>`, or with an
associated `<packageSourceCredentials>` block is excluded from resolution
entirely. Excluding a source does **not** by itself mean the affected
dependency shows no data: with no `<clear/>` in the chain, the exclusion just
falls back to the implicit `api.nuget.org` default — the same additive-source
model FR-003 already documents, since the excluded source is simply treated as
if it had never been declared. It becomes a hard failure only when the chain
also has a `<clear/>` (or an explicit `<remove key="nuget.org"/>`) in effect,
leaving nothing for the exclusion to fall back to. Key matching is
case-insensitive and additionally compares against NuGet's `_xHHHH_`-encoded
child-element-name form (a source named `Corp Feed` appears as
`<Corp_x0020_Feed>` under `<packageSourceCredentials>`).

**Authentication**: phase 1 carries **no** authentication at all, the same
Cargo/npm/PyPI precedent — a credentialed source fails closed per the previous
paragraph rather than being queried anonymously; `ClearTextPassword`/DPAPI-encrypted
`Password` values are never parsed into any retained field.

**Fail-closed on misconfiguration**: an invalid feed URL (non-https, userinfo,
malformed, a local/UNC filesystem path, or `protocolVersion="2"`) shows no
version data if it is the only remaining viable source, or is dropped (with a
logged warning) if other valid sources remain. A `<clear/>` that removes every
source down to zero — with or without an invalid entry left to name — is an
explicit fail-closed state, never a silent fallback to `api.nuget.org` (the
same issue #248/#502/#513 regression class Cargo/npm/PyPI already closed).

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented above for Cargo/npm/PyPI. Additionally, a workspace-declared
feed's own service-index resource URLs (`PackageBaseAddress`/
`SearchQueryService`/`RegistrationsBaseUrl`) are re-validated against this same
policy before being trusted — NuGet's service index is a two-hop indirection
(a top-level feed URL resolves to a JSON document naming further per-capability
resource URLs) with no equivalent in Cargo's/npm's/PyPI's single-URL registry
model, so a validated top-level host could otherwise redirect resolution to an
internal host via its own service index.

**Known limitations**:
- Editing `NuGet.Config` does not take effect until the affected manifest is
  next reparsed — no dedicated file watcher.
- `<packageSourceMapping><clear/>` is not honored — mapping rules only ever
  accumulate across the ancestor chain, never reset, even by a leaf file's own
  `<clear/>` inside that element. Deliberate: undoing the merge-not-nearest-wins
  fix for this one element needs its own empirical verification against real
  NuGet first.
- No authentication of any kind (see above) — an auth-gated private feed (Azure
  DevOps PAT, GitHub Packages token) is not reachable end-to-end until a
  follow-up auth spec ships.
- A workspace-declared feed's flat-container/service-index fetch loses
  origin-pinning (a redirect off the resolved `PackageBaseAddress` to another
  public host is permitted under `public_only`, unlike the origin-pinned
  transport `api.nuget.org` itself uses) and skips registration-hive
  enrichment entirely — no publish-time freshness data and no hover-only
  `*(unlisted)*` marker for a private-feed-resolved package.
- A dependency resolved to a private feed drops out of OSV vulnerability
  scanning, the deps.dev supply-chain signal, and the hover trust badge, and
  its hover heading omits the `nuget.org` package-page link (it would be
  misleading next to live private-feed data). Declaring
  `<packageSourceMapping>` narrows this considerably: only genuinely-private
  ids (ones that don't resolve to the real `api.nuget.org` source, identified
  by URL, never by a source's `key`) lose the signals. Without a mapping,
  adding one internal feed suppresses these signals for every dependency in
  the project, including ones still resolving from `api.nuget.org` via the
  implicit fallback hop.
- `complete_package_names` stays source-blind and always queries
  `api.nuget.org` — the typed string is a prefix, not a resolved private
  package name, so this is safe but not feed-aware (mirrors npm's/PyPI's
  identical choice).

### Yanked-Version Diagnostics

`diagnostics.yanked_severity` flags a dependency pinned to a version the registry
reports as yanked/deprecated/retracted, covering either the lock-file-resolved
version or an exact manifest pin (e.g. `requirements.txt`'s `==1.2.3`) when no lock
file exists. Checked for every dependency with a known in-use version — not only
one that differs from the registry's reported latest — since it is a free
in-memory lookup against the version list `deps-lsp` already fetched to compute
"latest", and only against a registry that exposes real per-version yank data.

This is one of two independent yanked-related diagnostics; see
[Yanked Version Diagnostic](#yanked-version-diagnostic) below for the other, which
flags a *requirement* (a range, not necessarily an in-use version) satisfiable only
by yanked versions. `deps-lsp` never emits both for the same dependency — see that
section for how the two are deduplicated.

| Ecosystem | Yanked diagnostic | Registry signal |
|-----------|--------------------|------------------|
| Cargo | Yes | crates.io sparse-index `yanked` |
| npm | Yes | npm `deprecated` |
| PyPI | Yes | PEP 592 per-file yank status |
| Bundler | Yes | RubyGems `yanked` |
| Dart | Yes | pub.dev `retracted` |
| Go | No | module proxy reports no retraction data |
| Maven | No | Maven Central has no retraction concept |
| Gradle | No | delegates to the same Maven Central registry as Maven |
| Swift | No | Swift package registries expose no per-tag yank signal |
| NuGet | No | unlisted versions are not distinguishable from listed ones today |
| Composer | No | Packagist's `abandoned` flag is package-level, not per-version — enabling it would fire on nearly every dependency of an abandoned package rather than the specific withdrawn release |
| Deno | Yes | JSR `meta.json` per-version `yanked` (genuine) for `jsr:` specifiers; npm `deprecated` (same package-level caveat as the npm row above) for `npm:` specifiers |

### PyPI Environment Markers (PEP 508)

When a Python dependency is gated by an environment marker (e.g., `numpy>=1.24; python_version>='3.9'`), the hover popup displays:
```
Active when: python_version >= '3.9'
```
This helps you understand when conditional dependencies apply. Markers are shown for dependencies in `pyproject.toml` (PEP 621), Poetry `[tool.poetry.dependencies]` tables, and both PEP 621 requirement strings and Poetry string-form suffixes.

### PyPI requirements.txt / constraints.txt

Files matching `requirements*.txt`, `*-requirements.txt`, `*.requirements.txt`, or `constraints*.txt` — or any `.txt` file directly inside a directory literally named `requirements/` (e.g. `requirements/base.txt`, `requirements/dev.txt`) — are routed to the PyPI ecosystem and parsed line-by-line (pip's requirements file format), reusing the same PEP 508 machinery as `pyproject.toml` — hover, diagnostics, markers and extras render identically across both. Comments, blank lines, `\`-continuations, per-requirement options (`--hash=...`), and recognized pip options (`-r`, `-c`, `-e`, `--index-url`, `--pre`, etc.) are handled; a `-r`/`-c`/`--requirement`/`--constraint` target is surfaced as a clickable `documentLink` resolved relative to the containing file's directory (ctrl/cmd-click to open it — its own dependencies are still checked only once it's open, not transitively from the referencing file). A pinned dependency (`django==5.0.1`) keeps its `==` pin on "update version" instead of widening to a range. Because neither the filename-pattern routing nor the `requirements/` directory convention is a fixed name, a non-manifest file that happens to match (e.g. a `product-requirements.txt` prose document, or a requirements-engineering docs file under an unrelated `requirements/` folder) is detected via a content heuristic and produces no hover/diagnostics/network requests — a file matched only via the `requirements/` directory convention requires a stronger signal (a recognized pip option, or a dependency with a version/URL) than a basename match does, since directory-name routing alone is weaker evidence that the file is really a Python manifest.

### PyPI Package-Name Completion

Package-name completion (issue #419) serves unranked, alphabetically-sorted prefix
matches from an in-memory index of PyPI's full Simple API project list (~882k names,
no popularity ranking) — the same approach PyCharm's PyPI completion uses, since PyPI
removed its XML-RPC search API and offers no first-party ranked search. The index is
built lazily (on the first completion request in a Python manifest) and once per
process, not refreshed on a timer.

Two behaviors worth knowing:
- **Completions insert the PEP 503 normalized spelling**, not the project's display
  spelling — `Django` is offered (and inserted) as `django`, `Zope.Interface` as
  `zope-interface`. This matches what `pip install` and both `poetry.lock`/`uv.lock`
  already normalize to.
- **Matching is prefix-only against the package name**, not a project's import name
  or description — typing `yaml` will not surface `pyyaml`, `sklearn` will not
  surface `scikit-learn`, and `bs4` will not surface `beautifulsoup4`. This is a
  known, common PyPI-specific expectation gap; a substring/import-name-aware search
  is tracked as a possible follow-up, not implemented here.

Because the index is capped and alphabetically sorted rather than ranked, the LSP
response for a package-name completion request sets `isIncomplete: true` so editors
re-query as the user keeps typing (`resolves #427`). This is scoped to the
package-name search itself — other completions in a Python manifest (versions,
comments, `[build-system]` positions) report `isIncomplete: false` like every other
ecosystem, since their result sets are already exhaustive.

### Maven/Gradle Version Comparison

Versions are now ranked with correct Maven semantics:
- **Numeric segments outrank non-numeric qualifiers**: `33` > `r09` (previously the reverse)
- **Prerelease qualifiers sort below their base release**: `1.0-RC1` < `1.0` (previously the reverse)
- **Qualifier precedence**: `alpha` < `beta` < `milestone` < `rc`/`cr` < `snapshot` < `release` < `sp` (case-insensitive)
- **Numeric suffixes within qualifiers are compared numerically**: `M10` > `M2` (previously `M2` > `M10`)

These fixes ensure hover's "Recent versions" list and completion sort order match Maven's actual version ordering.

### Dart/Composer Version Comparison

`compare_versions` previously discarded everything after the first non-digit character in a
dot-separated segment, so a prerelease/qualifier version compared as *equal* to its stable
counterpart (`2.0.0-beta1` tied with `2.0.0`). Both comparators now apply proper
prerelease-aware ordering:

- **Dart** (`pubspec.yaml`): SemVer 2.0.0 §11 precedence — numeric identifiers compare
  numerically, alphanumeric identifiers compare lexically (ASCII), and a version with a
  prerelease sorts below its base release. Applied both to "latest version" selection
  (pub.dev's response order) and to constraint matching, so hover/completion sort order and
  outdated diagnostics are both corrected.
- **Composer** (`composer.json`): stability precedence `dev` < `alpha` < `beta` < `RC` <
  `stable`, applied both to requirement-satisfaction comparison and to "latest version"
  selection. `select_latest_matching`/`get_latest_matching` exclude alpha/beta/RC releases by
  default (mirroring Composer's `minimum-stability: stable` default) unless overridden; a
  wildcard/existence-check requirement still resolves a prerelease-only package instead of
  reporting no version found. The effective stability floor is now manifest- and
  dependency-aware: a per-dependency `@stability` flag (`^1.0@beta`) or a directly-pinned
  prerelease version overrides the manifest's own `composer.json` `minimum-stability` field,
  which in turn overrides the `stable` default — reflected in the live "outdated" diagnostic,
  not just available as a library-level API. Separator-less and dot/underscore-separated
  prerelease suffixes (`1.0.0RC1`, `2.6.3.alpha`) classify consistently regardless of
  `v`/`V` prefix. Known limitation: editing `minimum-stability` alone in an already-open
  document does not refresh already-fetched dependencies' cached "latest" version until the
  document is closed and reopened.

### Maven/Gradle Version Range Matching

`version_satisfies_requirement` now recognizes bracket-interval range syntax instead of only exact string equality, so a dependency pinned to a range no longer always renders as "outdated":

- **Maven** (`pom.xml`): interval notation — `[1.0,2.0)`, `[1.0]` (exact pin), `[1.5,)`, `(,2.0]` — and top-level comma unions, e.g. `(,1.0),(1.2,)`. Bounds are compared with Maven's qualifier-aware ordering, so `[1.0-beta,2.0-rc)` orders correctly. A bare, non-bracketed requirement (`1.0`) is still Maven's "soft" recommended version and compared for plain equality, not as a range.
- **Gradle** (`build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml`): the same bracket-interval syntax as Maven (no comma unions — Gradle's grammar doesn't have them), plus Gradle-specific forms: dynamic versions (`1.0+`, `2.10.+`), `latest.release`/`latest.integration` selectors, and Gradle's reversed-bracket exclusive notation (`]1.2,1.5]` for an exclusive lower bound, `[1.1,2.0[` for an exclusive upper bound).
- **Malformed input fails closed**: an unparseable range (unbalanced/stray brackets, an extra comma-separated component, a mismatched no-comma pin like `[1.0)`, or any unparseable member of a Maven union) is rejected as a whole — `version_satisfies_requirement` returns `false` rather than matching on a corrupted or partial parse.

### Maven/Gradle Unresolved Requirements

A requirement that couldn't be resolved to a concrete version (Maven's `${property}` missing from `<properties>`, Gradle's `$var`/`${var}` variable reference, or a Gradle version-catalog `version.ref` alias missing from `[versions]`) is treated as `RequirementStatus::Unresolved`, distinct from `UpToDate`/`Outdated`:

- **Diagnostics**: no "Newer version available" hint is shown — same as before, since the server can't verify either way.
- **Inlay hints**: no badge is shown at all, neither "up to date" nor "needs update" — showing "up to date" for a requirement that was never actually checked against the latest version would be misleading.
- **CodeLens "Update N outdated dependencies"** (below): an unresolved requirement is also never counted or edited — it already fails the literal-span guard (the tracked span covers a placeholder/variable, not a version literal), so the two mechanisms agree independently rather than one depending on the other.

### Maven/Gradle Release-Freshness Coverage

Hover's "Recent versions" age suffix and completion's age `label_details` (gated by
`freshness.enabled`, default `true`) depend on Maven Central's `repo1.maven.org` HTML
directory listing, which is not available for every artifact source Maven/Gradle resolve
through:

- **Maven Central** (`repo1.maven.org`) ✅ — the directory listing is fetched and parsed;
  ages render normally.
- **Google Maven** (`dl.google.com`, `androidx.*`/`com.google.firebase.*`/
  `com.google.android.*`/`com.google.gms.*`/`com.android.*` group IDs) ✗ — the listing 404s
  for every artifact, so no extra request is even attempted; `published_at()` is always
  `None` and the version list itself is unaffected.
- **Gradle Plugin Portal** (`plugins.gradle.org`, the fallback for a group ID not found on
  Maven Central) ✗ — the listing has no date column; same result as above.

This is intentional graceful degradation (US-003), the same shape as Go's documented
partial freshness coverage (`/@v/list` carries no per-version dates either) — not a bug.

### NuGet/npm Release-Freshness Coverage

Both are gated by `freshness.enabled` (default `true`) like every other ecosystem, but each
pays for the signal differently:

- **NuGet** ✅, **but only for the newest ~8 versions of a package** — for any feed that
  exposes a `RegistrationsBaseUrl` resource in its service index (nuget.org always does),
  ages come from walking the registration hive's pages backwards from the newest, stopping
  once enough recent versions are covered. This is a deliberate MVP trade-off, not an
  oversight: completion filters by the typed prefix *before* truncating to the versions it
  renders, so a prefix that selects only older versions (e.g. typing `6.` against a package
  whose newest release is `9.x`) renders those versions with no age at all, even though
  hover on the same package shows ages normally (hover only ever renders the newest ~8
  anyway). A private V3 feed (Azure Artifacts, BaGet, GitHub Packages) that omits
  `RegistrationsBaseUrl` entirely degrades to `published_at: None` for every version, with
  the version list itself unaffected. Unlisted versions (the registration hive's
  `1900-01-01` sentinel date) never render a bogus age. Added cost is typically zero extra
  round trips (the version list and the registration index are fetched concurrently), one
  extra round trip when a package's registration hive externalizes its last page.
- **npm** ✅, but enabling it issues an **entire additional full-packument fetch** per
  package, not a marginal delta — the abbreviated packument `get_versions` already fetches
  carries no publish dates, so freshness attaches a separately-fetched, TTL'd (1 hour)
  `{version: date}` map derived from the full packument's `time` field instead. This is the
  one ecosystem in this project where `freshness.enabled: false` genuinely removes a whole
  request per hover/completion round, not just a conditional revalidation.

### Deno Freshness

`jsr:` specifiers get full freshness coverage at **zero extra request cost** — better than
both NuGet and npm above. JSR's `meta.json` (the same response `JsrRegistry::get_versions`
already fetches for the version list) carries a per-version `createdAt` timestamp, so
`published_at` is populated unconditionally with no separate fetch and no TTL to tune.
`npm:` specifiers in `deno.json` inherit npm's own freshness behavior exactly (see
NuGet/npm Release-Freshness Coverage above), since `DenoRegistry` delegates them to the
same `deps-npm` registry client `package.json` uses.

### CodeLens: "Update N Outdated Dependencies"

An open manifest with at least one outdated, safely-editable dependency shows a code lens at
the top of the document, titled `Update N outdated dependencies`. Clicking it applies a
single batch edit that rewrites every such dependency's version to the latest known
version, sharing the same "is this outdated" definition as diagnostics (a requirement
already satisfied by the latest version — e.g. Cargo's `^1.2` accepting `1.9` — is left
alone; that lag is the lock file's, not the manifest's, to fix).

**Coverage caveat.** Before rewriting a dependency's declared version text, the feature
verifies the manifest span it is about to edit actually *is* that version literal. Some
ecosystems point the tracked span at something else instead:

- **`pom.xml`** dependencies versioned through a `<properties>` placeholder (`<version>${my.version}</version>`) are skipped — the span covers the placeholder, not a literal.
- **Gradle** dependencies versioned through a DSL variable (`"...:$myVersion"`, resolved from `gradle.properties`) or a `libs.versions.toml` version-catalog alias (`version.ref = "spring"`) are skipped for the same reason.
- **`Package.swift`** dependencies declared with a two-literal range (`"1.0.0"..<"2.0.0"` or `"1.0.0"..."1.9.9"`) are skipped — the tracked span covers only the range's lower-bound literal, and rewriting that literal alone would invert the range (SwiftPM traps on `lowerBound > upperBound`, corrupting the whole manifest) rather than leave a merely-stale-but-valid declaration.

For these, no lens appears even when the dependency is genuinely outdated — this is the
correct, conservative behavior (silently declining to edit is far better than corrupting a
build file), not a bug. The per-line "Update to latest version" code action shares the exact
same guard, so it declines the same way rather than corrupting these declarations.

`Package.swift`'s other declaration forms (`from:`, `.upToNextMajor`, `.upToNextMinor`,
`.exact`) were affected by this same guard through #367: each synthesizes a comparator
requirement (e.g. `.exact("4.50.0")` -> `=4.50.0`) that never textually matched the bare
version literal the tracked span actually points at, so the guard rejected every one of
them and both the lens and the code action silently did nothing. Fixed by having
`deps-swift` additionally report the bare literal (`Dependency::version_literal()`) the
guard should compare against; these four forms now get a lens and code actions like any
other registry-form dependency (`.branch`/`.revision`/`.package(path:)` dependencies still
have no version to update, same as any other ecosystem's git/path dependency, and the two
range forms above remain guard-skipped by design).

Only the six documented `.package(...)` spellings above are parsed at all — a handful of
other valid SwiftPM argument-label combinations (`.package(url:exact:)`, `.package(url:
branch:)`/`(url:revision:)`, `.package(id:...)`, the legacy `.package(name:url:...)`, or any
of the above with a trailing comma) currently parse to zero dependencies rather than a
skipped one; extending parser coverage to them is tracked separately, out of scope here.

**Known divergence from inlay hints (accepted, documented).** Inlay hints use a
lock-file-aware "outdated" check (resolved version vs. latest), while the lens and
diagnostics use the manifest-requirement check described above. With a lagging lock file
and a requirement permissive enough to already accept the latest version, inlay hints can
render `❌ <version>` on a dependency with no matching diagnostic and no lens — the fix
in that case is regenerating the lock file, which only the package manager can do, so
there is nothing for the lens to edit. Unifying the two definitions is tracked as a
follow-up.

### Code Action: Fix Vulnerability

A dependency flagged by the OSV vulnerability scan (see the security-advisories hover
section and diagnostics) gets an extra code action alongside the plain "update to
version X" list: a quickfix titled `Update to <version> (fixes <ADVISORY-ID>[ +N more])`,
naming only the worst-severity advisory id and summarizing the rest so the title stays
readable in an editor's code-action menu (the full id list still travels with the action
so editors can bind it to the matching diagnostics — see below). The target version is the
*lowest* version that resolves every advisory the action claims to fix: an advisory OSV
reports as still applying at the checked candidate (from the scan's second-phase check) is
excluded from the claim, and — crucially — excluded *before* the target version is picked,
so that advisory's own fix version (which may be much higher) can never inflate the
recommendation past what the claimed advisories actually need.

The action is independent of the registry fetch that produces the plain update list, so a
registry outage never hides it. When the registry fetch does succeed, a fix version the
registry reports as yanked is dropped instead of offered (no action, rather than silently
retargeting to some other version), and a fix version whose *formatted* manifest text
already matches the dependency's declared requirement is skipped as a no-op edit — the
comparison uses the actual text the edit would write, not the bare version, since several
ecosystems format it differently (Dart wraps it in a `^` constraint, PyPI expands it into a
`>=,<` range). If the scanned version came from the lock file rather than the declared
requirement, the title gets an `; update lockfile to apply` suffix, since editing the
manifest alone will not clear the diagnostic until the lock file is regenerated.

Editors that support diagnostic-bound quickfixes (surfacing the action from the advisory's
own lightbulb rather than only the generic code-action menu) get this automatically: the
action carries its resolved advisory ids internally, and `deps-lsp` binds it to any
matching diagnostic the client already reported for the same range. Filtering code actions
by kind (e.g. an editor's "quick fix only" view) is also honored.

**Go note.** The formatter hook this action relies on to convert an OSV-reported version
into `go.mod`'s `v`-prefixed form is in place, but Go's vulnerability scan currently sends
the `v`-prefixed module version to OSV, which expects it unprefixed, and gets no matches
back (tracked separately) — so no Go dependency can trigger this action yet.

### Unsatisfiable Version Requirement

When a dependency's declared version requirement matches **zero published versions** — of
any kind, stable, prerelease, or yanked — deps-lsp shows a WARNING diagnostic:

```
No published version satisfies requirement '99'; latest is 1.0.214
```

This is distinct from `Unknown package` (the package itself was not found) and from the
"Newer version available" HINT (a satisfiable requirement that simply isn't pinned to the
latest release). The two are mutually exclusive on the same dependency — a requirement is
either up to date, outdated-but-satisfiable, or unsatisfiable, never more than one at once.

The check is always on (no configuration flag) across 12 of the 13 ecosystems — GitHub
Actions does not opt in (a pin is not a range, so there is no "requirement satisfies zero
versions" question to ask) — and is deliberately conservative:

- **Suppressed while versions are still loading**, or if the registry fetch failed — an
  empty/unknown version list means "don't know yet", not "nothing published".
- **Suppressed for path/git/URL/SDK/workspace dependencies** — their `version` field, if
  present, does not refer to something resolvable against the ecosystem's package registry
  at all (e.g. this project's own `deps-core = { path = ..., version = "0.10.1" }`, or
  Dart's `{ sdk: flutter, version: "^3.24.0" }`, which resolves against pub.dev's unrelated
  package literally named `flutter`).
- **Suppressed for an unresolved requirement** — a dangling Gradle version-catalog
  `version.ref` alias or an unexpanded Maven `${property}` was never actually checked
  against anything.
- **A prerelease-only or yanked-only match still counts as satisfied** — neither triggers
  this WARNING. `foo = "2.0.0-beta.1"` is a deliberate opt-in, and a yanked version is still
  installable when pinned (Cargo resolves yanked versions present in the lock file); flagging
  either as unsatisfiable would be a false positive. A yanked-only match is not silent,
  though — it surfaces instead as the separate [Yanked Version](#yanked-version-diagnostic)
  diagnostic below.
- **Suppressed for requirement forms naming a version outside the fetched candidate list by
  construction**, not just failing to match one present in it — Go pseudo-versions and
  `dev-*`/`*-dev`/`@dev` Composer branches (never enumerable from the registry list at all),
  and Maven/Gradle `-SNAPSHOT`/`LATEST`/`RELEASE` (resolved via a different repository/side
  channel this registry never queries).
- **RubyGems exact pins are suppressed only when the pin does not exceed the highest
  published version.** RubyGems' `versions.json` omits yanked versions from the list with no
  flag to detect them, so a pin that could plausibly name a hidden yanked version is not
  flagged. A pin above every published version — a mistyped or genuinely unpublished version,
  e.g. `gem "foo", "99.0.0"` when `foo` tops out at `2.0` — is still flagged as unsatisfiable.
- Each ecosystem opts in by implementing a precise per-version-format comparator (the same
  crate its registry client already depends on: `semver` for Cargo/Swift, `node-semver` for
  npm, `pep440_rs` for PyPI, bracket-interval range parsers for Maven/Gradle/NuGet, and
  exact/pattern comparators for Go/Bundler/Dart/Composer) — not the same loose heuristic
  used for the "up to date" hint, which is intentionally permissive and would produce false
  positives if reused here (e.g. Cargo's `~1.0.999` reads as "up to date" against a latest
  of `1.0.214` under the loose same-major-minor heuristic, despite patch `999` never having
  been published).
- **Cargo, npm, and Swift additionally name a matching pre-release, if one exists.** These
  three ecosystems use a strict SemVer-style matcher that excludes prereleases unless the
  requirement itself names one — so a requirement like `^2.0.0` reads as fully unsatisfiable
  even when a `2.0.0-rc.1` has been published. The WARNING then appends a clause naming it:
  ```
  No published version satisfies requirement '^2.0.0'; latest is 1.5.0 (a pre-release,
  2.0.0-rc.1, is excluded by SemVer's default pre-release-matching rules; require it
  explicitly to use it)
  ```
  The hint is skipped when the requirement itself already names a pre-release (the real
  blocker there is version ordering, not pre-release exclusion) and when the only matching
  pre-release has been yanked. Maven/NuGet/Composer/Gradle's range-parsing model already
  admits prerelease qualifiers within a range and is unaffected.

**Not yet implemented:** a separate informational diagnostic for a requirement that only
matches prerelease versions.

### Code Action: Fix Unsatisfiable Requirement

A dependency flagged by the diagnostic above gets a `QUICKFIX` titled `Fix unsatisfiable
requirement: update to <version>`, targeting the same cached `latest` value the diagnostic
message names, so the action's title and the diagnostic text always agree on what "the
latest" is. The action is gated by the identical unsatisfiability check the diagnostic uses,
so the action never appears without the diagnostic — though, as described below, several
further guards (a yanked target, a no-op or still-unsatisfiable rewrite, a text collision
with the vulnerability fix) can independently suppress the action while the diagnostic
itself stays up.

Like the vulnerability fix above, this action is computed before the registry fetch that
produces the plain update list, so a registry outage never hides it. When the fetch does
succeed, a target the registry reports as yanked is dropped rather than offered. The
rewritten text is re-checked against the same unsatisfiability predicate before the action
is returned, since an ecosystem that preserves operator style when rewriting a requirement
(PyPI, Gradle) can otherwise produce another still-unsatisfiable range; this re-check cannot
prove a rewrite it cannot evaluate is correct, so it holds for every rewrite the ecosystem's
own comparator can judge, not unconditionally.

If both this action and the vulnerability fix apply to the same dependency and would write
byte-identical text, the vulnerability fix (the more informative title) is kept and this one
is dropped. At most one action across the whole response is ever marked as the editor's
preferred quickfix, in priority order: vulnerability fix, then unsatisfiable-requirement fix,
then the REFACTOR item pointing at the newest available version.

Editors that support diagnostic-bound quickfixes get this automatically, the same way as the
vulnerability fix: the action binds to any matching diagnostic the client already reported
for an overlapping range.

### Yanked Version Diagnostic

The other of the two independent yanked-related diagnostics — see
[Yanked-Version Diagnostics](#yanked-version-diagnostics) above for the in-use-version
check. When a dependency's declared version requirement is satisfiable, but **every**
version that satisfies it has been yanked/deprecated by the registry, deps-lsp shows a
WARNING diagnostic (configurable via `diagnostics.yanked_severity`):

```
This version has been yanked
```

This only fires when at least one matching version exists and all matching versions are
yanked — the same scan `Unsatisfiable Version Requirement` above uses (via
`EcosystemFormatter::compile_requirement`), cross-referenced against the registry's yanked
flags. It is mutually exclusive with both the unsatisfiable WARNING (a yanked-only match is
a satisfied match, not zero matches) and the outdated/up-to-date check. If a non-yanked
version also satisfies the requirement (e.g. `^1.0` matching both a yanked `1.0.0` and a
non-yanked `1.0.1`), this diagnostic does not fire — the dependency is not actually stuck on
a yanked version, and the ordinary outdated/up-to-date check applies instead.

It is also mutually exclusive with the in-use-version [Yanked-Version
Diagnostics](#yanked-version-diagnostics) check above: for a dependency pinned to the one
version that also happens to be the only version satisfying its own requirement, both checks
would independently find a yanked verdict, but `generate_diagnostics_from_cache` skips this
check once the in-use-version check has already emitted a diagnostic for the same
dependency, so only one yanked diagnostic is ever shown per dependency.

- **npm is disabled entirely; Composer is restricted to exact-pin requirements.** Both source
  their yanked flag from a package-wide signal — npm's from `deprecated` (live-verified: the
  `request` package has 126/126 versions marked deprecated), Composer's from `abandoned` — not
  a true per-version yank, which is why this is a distinct diagnostic from [Package
  Deprecation Diagnostics](#package-deprecation-diagnostics-issue-205) below rather than the
  same one. For npm, evaluating *any* requirement shape against that package-wide signal —
  including a bare exact pin — would too often just duplicate the package-level deprecation
  diagnostic, so this check is unconditionally off for npm (resolves #436); this also covers
  Deno's `npm:` specifiers, which delegate to npm's own registry data (resolves #448). For
  Composer, evaluating a range requirement against it would flag every dependency on an
  abandoned package, so a bare exact pin (`"1.2.3"`, not `"^1.2.3"`) is unaffected by that
  ambiguity and the check still applies there. Deno's `jsr:` specifiers are unrestricted (any
  requirement shape): JSR's `meta.json` `yanked` flag is a true per-version signal with no
  package-level deprecation payload to conflate with, unlike npm/Composer above (resolves
  #454).

**Ecosystem coverage, live-verified per registry rather than assumed from code:**

| Ecosystem | Works today? | Source |
| --------- | ------------- | ------ |
| Cargo | Yes | sparse index `yanked` field |
| npm | No | `deprecated` exists but the check is unconditionally off (see restriction above) |
| PyPI | Yes | PEP 592 `yanked` |
| Composer | Yes, exact pins only | `abandoned` (see restriction above) |
| Dart | Yes | pub.dev `retracted` |
| Bundler | No | RubyGems' `versions.json` never includes a `yanked` field on any entry (live-verified against the API directly) — indistinguishable from a version that never existed, same limitation the `Unsatisfiable Version Requirement` check documents above |
| Go | No | `GoVersion.retracted` is hardcoded `false` at both construction sites in `deps-go`'s registry client — the field exists but is never populated from real data (tracked separately) |
| Maven | No | `MavenVersion::is_yanked` is a hardcoded `false` constant — Maven Central does not support version retraction |
| Gradle | No | reuses Maven Central's registry client, same hardcoded `false` |
| NuGet | No | `NuGetVersion::is_yanked` is a hardcoded `false` constant |
| Swift | No | `SwiftVersion.yanked` is a field that is always `false` for GitHub tags (no such concept in the source) |
| Deno | `jsr:` yes, any requirement shape; `npm:` no | JSR `meta.json` per-version `yanked` for `jsr:` specifiers; npm `deprecated` (unconditionally off, see restriction above) for `npm:` specifiers |
| GitHub Actions | No | GitHub's tags API exposes no yank/deprecation signal for actions — `GithubActionsRegistry::reports_yanked` is hardcoded `false`, same architectural gap as Swift |

5 of 13 ecosystems can produce this diagnostic today; npm is disabled by design rather than
lacking a real signal (see restriction above), and that also covers Deno's `npm:` specifiers;
the remaining 7 have no real yanked signal to source it from (four are architecturally
impossible — no such registry concept exists — and Go's is a fixable but separate gap).

### Package Deprecation Diagnostics (issue #205)

The two yanked diagnostics above answer "is *this version* installable"; this one answers a
different, package-level question — "is the project itself still maintained" — regardless of
which version is declared or resolved. When the registry reports the package's latest version
as deprecated/abandoned, `deps-lsp` shows a diagnostic (configurable via
`diagnostics.deprecated_severity`, default WARNING):

```
This package is deprecated: use String.prototype.padStart() instead
```

The hover popup gets a matching `### Deprecated` section with the same reason text and, when
the registry names one, a suggested replacement package. Derived entirely from data the
regular version fetch already retrieves — no extra registry request.

**Suppression against the yanked diagnostics above.** npm's yanked signal is itself sourced
from the same `deprecated` field this diagnostic reads, so a dependency pinned to an exact,
deprecated version would otherwise show two near-duplicate diagnostics. When this diagnostic
fires, it suppresses *both* yanked checks above for the same dependency — the in-use-version
check and the range-requirement-only-satisfiable-by-a-flagged-version check — but only when
the matched yanked finding's underlying signal is an advisory (`AdvisoryDeprecated`), never a
genuine hard yank/retraction. A package that is both deprecated *and* has a specific version
really withdrawn from resolution still shows both diagnostics; "the exact version you have was
pulled" is strictly more actionable than "the project is archived," and one must never hide
the other.

Each of the two yanked checks decides this independently from its own matched version's
`RemovalStatus` (issue #437) — the range check does not defer to, or require, the
in-use-version check's own finding. This matters once an ecosystem's per-version status can be
`AdvisoryDeprecated` for one version and `Yanked` for another within the same package (not
possible for npm/Composer today, since npm never reports a real yank and Composer's range
check never runs, but expected once PyPI's PEP 592 yanks and PEP 792 `project-status` coexist):
a range requirement satisfiable only by a genuinely yanked version still fires even when the
package's separately-tracked in-use/latest version is merely deprecated and its own diagnostic
was suppressed.

**Composer-only "Replace with X" code action.** When Packagist's `abandoned` field names a
successor package, a `QUICKFIX` titled `Replace with <package>` rewrites the dependency's name
in place. Not offered for npm: its only successor signal is free-text prose inside the
`deprecated` message, and regex-extracting a package name from registry-controlled text to
rewrite a manifest is a typosquatting vector — npm still gets the diagnostic and hover (the
message is shown verbatim, which is the useful part), just not an automated rename.

| Ecosystem | Works today? | Source |
| --------- | ------------- | ------ |
| npm | Yes | `deprecated` free-text message (no structured replacement — see above) |
| Composer | Yes, with replace action | `abandoned` (bare `true`, or a string naming a successor package) |
| Cargo, Go, PyPI, Bundler, Dart, Maven, Gradle, Swift, NuGet, Deno | Not yet | No registry-native package-level deprecation signal wired up yet (tracked as fast-follows; Dart's `isDiscontinued`/`replacedBy` and PyPI's PEP 792 `project-status` already exist on the wire and are the best next targets) |

### Mutable-Ref-Pin Diagnostic (issue #473)

**GitHub Actions only.** A `uses:` step pinned to a mutable ref — a tag (`actions/checkout@v4`)
or, in a future iteration, a branch — can silently start running different code than the
workflow file shows: a compromised or republished tag changes what CI executes without a single
line of the workflow file changing. This is a distinct, additive signal from the outdated-version
diagnostic above (configurable via `diagnostics.mutable_ref_pin_severity`, default HINT) — a step
can be up to date on its tag and still vulnerable to tag mutation, so both diagnostics can fire
independently on the same step with distinct codes:

```
actions/checkout is pinned to the mutable tag ref `v4`; pin to a full commit SHA to guard against tag mutation
```

The diagnostic fires for two kinds of tags:
- **Semantic-version-shaped tags** (`v1.2.3`, `v4.0`, etc.) — detected by text pattern and confirmed via the registry.
- **Literal-named tags** (non-version-like names such as `cargo-deny`, `latest-stable`) — these do not look tag-shaped to the parser, but when the registry confirms they are real tags, they become eligible for this diagnostic too (issue #551).

Unlike every other diagnostic in this project, severity alone cannot silence this one —
`DiagnosticSeverity` has no suppression value. Set `diagnostics.mutable_ref_pin_enabled` to
`false` in initialization options to turn it off entirely for teams that intentionally accept
tag pinning.

**"Pin `<name>` to commit SHA" quick fix.** When offered, rewrites the step's ref to
`<sha> # <tag>` — the exact same `{sha} # {tag}` shape the outdated-SHA-update quick fix already
produces for a SHA-pinned step, reusing the tag/SHA cross-reference already populated by the
existing outdated-version check (zero new network calls). The quick fix is withheld, not offered
with a wrong or destructive edit, in three cases:

- The tag's commit SHA is not yet known — e.g. the document was opened before the registry fetch
  completed, or the tag was moved/deleted/is not a full `major.minor.patch` release the registry
  indexes (a moving major-version ref like `v4` itself is frequently in this category — GitHub's
  tags API lists `v4.3.1`, not a synthetic `v4` tag object).
- **For literal-named tags**, even if the SHA is known, the quick fix is deliberately withheld (safety boundary FR-005) — a literal tag name like `cargo-deny` could in principle be a typo for a branch name, and silently replacing it with an auto-rewritten SHA would lock workflow behavior in place without the author's explicit intent. The diagnostic still fires so you know the tag is mutable, but the fix requires manual intervention to avoid accidental branch/tag confusion.
- The `uses:` value is a **quoted YAML scalar** (`uses: "actions/checkout@v4"`). The ref text
  sits inside the quotes there, so appending `# <tag>` would place a `#` inside the string rather
  than starting a YAML comment — a `uses:` value GitHub Actions rejects. Re-pin a quoted step by
  hand, or remove the quotes first.

**Out of scope for this iteration:** branch pins (`@main`) get no diagnostic yet — no
tag-to-SHA-style index exists for branches, and adding one would require a new network call per
branch; reusable-workflow calls (`owner/repo/.github/workflows/x.yml@ref`) and `./local`/
`docker://` references are not resolvable refs and get no diagnostic either.

### GitHub Actions: Non-Semver Tag Handling (issue #550)

When a GitHub Action repository has only tags that don't parse as full semantic versions — such as
`dtolnay/rust-toolchain` with its sole tag `v1`, or literal-named tags like `cargo-deny` — the
hover and diagnostics now handle these gracefully instead of showing a false "Unknown package"
diagnostic.

- **Hover**: shows the package as resolvable (not unknown), but with an empty "Recent versions" list since no tag matches the standard semver filter. The mutable-ref-pin diagnostic still fires for the tag ref even though no update-to-latest is available.
- **Diagnostics**: the package is recognized as resolvable, not reported as "Unknown package" — this is a real action, just not one with a conventional semver release train.
- **Literal-named tags** (non-version-like names): are now recognized as actual tags (when confirmed by the registry) and qualify for the mutable-ref-pin diagnostic, even though they don't follow the `major.minor.patch` or `v\d+` patterns the parser heuristic would normally detect.

### Supply-Chain Trust Signal (issue #543)

Hover can show an additional, informational line for a dependency's upstream supply-chain
health, sourced from [deps.dev API v3](https://docs.deps.dev/api/v3/) — a free, keyless,
cross-ecosystem metadata API. Two independent pieces of data are shown together on one line:

```
🔐 Supply chain: OpenSSF Scorecard `8.5`/10 · Provenance: verified
```

- **OpenSSF Scorecard** — the linked source repository's aggregate score (0-10), from checks
  like Code-Review, Dangerous-Workflow, Maintained, and Branch-Protection.
- **Build provenance** — whether the *specific resolved version* has a verified build
  provenance or attestation: `verified` (at least one `slsaProvenances[]`/`attestations[]`
  entry is verified), `attested but unverified` (an entry exists but none is verified — shown
  rather than silently omitted, so "we checked and found nothing" is never confused with "we
  didn't check"), or `none found` (no provenance data at all for this version). Labeled plainly
  as "Provenance", not "SLSA provenance": the two arrays are unioned, and an `attestations[]`
  entry is not necessarily SLSA-specific.

Both halves render independently — a package with a Scorecard but no provenance data (or vice
versa) shows only the half that resolved. The section is omitted entirely, with no error or
warning, whenever deps.dev has nothing to offer: an unsupported ecosystem, no linked source
repository, a deps.dev outage, or no concrete in-use version for the dependency (a lock-file-
resolved version, or an exact requirement pin — the provenance claim is version-specific, so no
in-use version means nothing safe to query).

**Self-reported repository disclosure.** A package can carry several `SOURCE_REPO` links to
deps.dev, distinguished by whether the link is `SLSA_ATTESTATION`-backed (cryptographically
tied to the published artifact) or merely `UNVERIFIED_METADATA` (taken from the package's own,
unverified manifest metadata). `deps-lsp` prefers the attested link; when only a self-reported
one exists, the score is still shown but marked `*(self-reported repo)*` — a package could
otherwise point its metadata at an unrelated, reputable repository and borrow its Scorecard.

**Coverage.** deps.dev covers **npm, Cargo, Go, Maven, PyPI, Bundler, and NuGet** — Composer,
Dart, and Swift have no deps.dev coverage and issue zero requests for this signal. Gradle and
Deno's `npm:` specifiers are not covered by this iteration either, though deps.dev's `maven`
system would cover Gradle coordinates without further mapping work.

**Performance.** The fetch runs as a detached background task alongside the dependency's normal
registry fetch, bounded by a short wait budget on the hover response itself — a slow or
first-ever (cold-cache) deps.dev lookup never delays or blocks any other hover content, and an
over-budget fetch still finishes into an in-process cache so the *next* hover on that dependency
is instant. Set `supply_chain.enabled` to `false` to turn the signal (and every deps.dev
request) off entirely — see the [Configuration reference](../README.md#configuration-reference).

Informational only, permanently: a low Scorecard score never becomes a diagnostic, warning, or
blocking behavior, matching the release-freshness signal's precedent for a
supply-chain-risk-adjacent hover addition.

### npm Package Name Validation

When a dependency in `package.json` fails to resolve against the npm registry, the diagnostic distinguishes between two cases instead of always reporting "Unknown package":

- **`Invalid package name '<name>': <reason>`** — the name itself violates npm's own naming rules (e.g. it starts with `.`/`_`, exceeds 214 characters, contains a character outside npm's URL-friendly set, or is a reserved name like `node_modules`).
- **`Unknown package '<name>'`** — the name is syntactically valid but was not found in the registry (typo, private/unpublished package, etc.).

The check is deliberately permissive: uppercase names are still accepted (npm only warns on those for legacy packages, never rejects), and it accepts every character npm's own `encodeURIComponent(segment) === segment` predicate accepts, including `! ' ( ) * - . _ ~` — not just alphanumerics and hyphens.

### Swift and GitHub Actions Release-Freshness Coverage

Unlike the ecosystems whose registry already carries a publish timestamp, Swift and GitHub
Actions both source package versions from GitHub's `tags` API, which has no date field.
`deps-swift` and `deps-github-actions` each augment their tag-derived version list with publish
times from GitHub's *releases* API (one extra request per package, memoized behind a TTL) via the
same shared `deps_core::github::ReleaseDatesCache` (#486) — but this makes both ecosystems'
freshness signal **partial**, in four distinct ways:

- **Requires `GITHUB_TOKEN`.** Without it, hover and completion render versions exactly as they
  did before this feature — no publish age shown, no error. A one-time `tracing::info!` notes the
  skip on first use (`export GITHUB_TOKEN=$(gh auth token)` to enable it).
- **Covers only versions with a matching GitHub Release.** A tag with no corresponding Release
  shows no date. Coverage of the versions actually rendered is high but not universal even among
  recent versions — one real-world counterexample (`SwiftyJSON/SwiftyJSON`) is missing dates for
  two of its eight most recent tags.
- **Reports Release *publish* time, not tag-creation time.** If a maintainer tags a commit and
  only publishes the GitHub Release for it later, the date reflects the Release, which can read
  as more recent than when the code was actually written. There is no cheap way to distinguish
  this from a genuinely fresh release.
- **Covers roughly the 100 newest releases only** (one unpaginated API page). Browsing completions
  filtered to an older major version line can show no dates at all, even though the same package's
  newest versions do — this is a known, accepted inconsistency within a single session.

A miss in any of the above degrades to no date shown, never a wrong one. GitHub Actions inherits
this coverage verbatim (same shared cache, same `/releases` endpoint) — the one difference is the
join key: a GHA `uses:` step's tag keeps its `v` prefix as published in the version list, so the
join normalizes it before matching against the releases map, while Swift's tag-derived versions
are already normalized at parse time.

## Architecture Overview

Each ecosystem is implemented as a separate crate under `crates/deps-{ecosystem}/` with the following structure:

```
crates/deps-{ecosystem}/
├── Cargo.toml
└── src/
    ├── lib.rs          # Re-exports and module declarations
    ├── ecosystem.rs    # Ecosystem trait implementation
    ├── error.rs        # Ecosystem-specific error types
    ├── formatter.rs    # Version display formatting
    ├── lockfile.rs     # Lock file parsing
    ├── parser.rs       # Manifest file parsing with position tracking
    ├── registry.rs     # Package registry API client
    └── types.rs        # Dependency, Version, and other types
```

## Step 1: Create the Crate

Create a new crate with workspace dependencies:

```toml
# crates/deps-{ecosystem}/Cargo.toml
[package]
name = "deps-{ecosystem}"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
description = "{Ecosystem} support for deps-lsp"

[dependencies]
deps-core = { path = "../deps-core" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tower-lsp-server = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tokio-test = { workspace = true }
```

Add to workspace in root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing members
    "crates/deps-{ecosystem}",
]
```

## Step 2: Handle Errors

Construct `deps_core::DepsError` directly at call sites instead of using a local error wrapper. Use `deps_core::Result<T>` for function signatures:

```rust
use deps_core::DepsError;

/// Example: validation function
fn validate_module_path(path: &str) -> deps_core::Result<()> {
    if path.is_empty() {
        return Err(DepsError::InvalidVersionReq("module path is empty".into()));
    }
    if path.contains("..") {
        return Err(DepsError::InvalidVersionReq(
            format!("invalid module path: {}", path)
        ));
    }
    Ok(())
}

/// Example: parsing function
fn parse_manifest(content: &str, uri: &Uri) -> deps_core::Result<ParseResult> {
    // Parse logic...
    // On error: return Err(DepsError::ParseError { ... })
    // On success: return Ok(ParseResult { ... })
}

/// Example: registry function handling 404
const REGISTRY: &str = "example-registry";

fn fetch_versions(package: &str) -> deps_core::Result<Vec<Version>> {
    let response = http_client.get(&url).send()
        .map_err(|e| DepsError::CacheError(e.to_string()))?;
    
    if response.status() == 404 {
        return Err(DepsError::PackageNotFound {
            package: package.into(),
            registry: REGISTRY,
        });
    }
    
    let data: Vec<Version> = response.json()
        .map_err(|e| DepsError::ApiResponse {
            package: package.into(),
            registry: REGISTRY,
            source: e,
        })?;
    
    Ok(data)
}
```

## Step 3: Define Types

Create ecosystem-specific types in `types.rs`:

```rust
//! Types for {Ecosystem} dependency management.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

pub use deps_core::parser::DependencySource;

/// A dependency from the manifest file.
#[derive(Debug, Clone)]
pub struct {Ecosystem}Dependency {
    /// Package name
    pub name: deps_core::PackageName,
    /// LSP range of the name in source
    pub name_range: Range,
    /// Version requirement (e.g., "^1.0", ">=2.0")
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of version in source
    pub version_range: Option<Range>,
    /// Dependency source (registry, git, path)
    pub source: DependencySource,
    /// Dependency section (dependencies, dev, etc.)
    pub section: {Ecosystem}DependencySection,
}

/// Dependency section types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum {Ecosystem}DependencySection {
    Dependencies,
    DevDependencies,
    // Add ecosystem-specific sections
}

/// Version information from the registry.
#[derive(Debug, Clone)]
pub struct {Ecosystem}Version {
    pub version: deps_core::ConcreteVersion,
    pub yanked: bool,
    // Add ecosystem-specific fields
}

// Implement deps_core traits
impl deps_core::Dependency for {Ecosystem}Dependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_req.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> DependencySource {
        self.source
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl deps_core::Version for {Ecosystem}Version {
    fn version_string(&self) -> &deps_core::ConcreteVersion {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn is_prerelease(&self) -> bool {
        // Implement based on ecosystem's prerelease conventions
        let version = self.version.as_str();
        version.contains('-') || version.contains("alpha") || version.contains("beta")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
```

## Step 4: Implement the Parser

Create manifest parser in `parser.rs` with **position tracking**:

```rust
//! {Manifest} parser with position tracking.

use crate::error::Result;
use crate::types::{Ecosystem}Dependency;
use std::any::Any;
use tower_lsp_server::ls_types::{Uri};
use deps_core::lsp_helpers::LineOffsetTable;

/// Parse result containing dependencies and metadata.
#[derive(Debug)]
pub struct {Ecosystem}ParseResult {
    pub dependencies: Vec<{Ecosystem}Dependency>,
    pub uri: Uri,
}

impl deps_core::ParseResult for {Ecosystem}ParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None // Override if ecosystem supports workspaces
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Parse manifest file and extract dependencies with positions.
pub fn parse_{manifest}(content: &str, uri: &Uri) -> Result<{Ecosystem}ParseResult> {
    let line_table = LineOffsetTable::new(content);

    // TODO: Implement actual parsing logic
    // Key requirements:
    // 1. Track byte offsets for every dependency name and version
    // 2. Convert offsets to LSP Position using line_table.byte_offset_to_position(content, offset)
    // 3. Handle all dependency sections

    Ok({Ecosystem}ParseResult {
        dependencies: vec![],
        uri: uri.clone(),
    })
}
```

## Step 5: Implement the Registry Client

Create registry client in `registry.rs`:

```rust
//! {Registry} API client with HTTP caching.

use crate::types::{Ecosystem}Version;
use deps_core::{DepsError, HttpCache, Result, ecosystem::BoxFuture};
use std::any::Any;
use std::sync::Arc;

const REGISTRY_URL: &str = "https://registry.example.com";

/// {Registry} API client.
pub struct {Ecosystem}Registry {
    cache: Arc<HttpCache>,
}

impl {Ecosystem}Registry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<{Ecosystem}Version>> {
        let url = format!("{}/{}", REGISTRY_URL, urlencoding::encode(name));

        let data = self.cache
            .get_cached(&url)
            .await
            .map_err(|e| DepsError::CacheError(e.to_string()))?;

        // TODO: Parse response and return versions
        Ok(vec![])
    }

    /// Gets the latest version matching a requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        version_req: &str,
    ) -> Result<Option<{Ecosystem}Version>> {
        let versions = self.get_versions(name).await?;

        // TODO: Implement version matching logic
        Ok(versions.into_iter().find(|v| !v.yanked))
    }
}

// Implement deps_core::Registry trait using BoxFuture (no async_trait).
// The trait takes PackageName/VersionReq; the inherent methods above stay
// &str, so each forward converts with .as_str().
impl deps_core::Registry for {Ecosystem}Registry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
    ) -> BoxFuture<'a, deps_core::error::Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self.get_latest_matching(name.as_str(), req.as_str()).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

## Step 6: Implement the Ecosystem Trait

Create the main ecosystem implementation in `ecosystem.rs`:

```rust
//! {Ecosystem} implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{Position, Uri};

use deps_core::{
    Ecosystem, HttpCache, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    ecosystem::BoxFuture,
    lockfile::LockFileProvider,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::{Ecosystem}Formatter;
use crate::lockfile::{Ecosystem}LockfileParser;
use crate::parser::parse_{manifest};
use crate::registry::{Ecosystem}Registry;

/// {Ecosystem} ecosystem implementation.
pub struct {Ecosystem}Ecosystem {
    registry: Arc<{Ecosystem}Registry>,
    formatter: {Ecosystem}Formatter,
}

impl {Ecosystem}Ecosystem {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: Arc::new({Ecosystem}Registry::new(cache)),
            formatter: {Ecosystem}Formatter,
        }
    }
}

// Required sealed trait impl — prevents external implementations
impl deps_core::ecosystem::private::Sealed for {Ecosystem}Ecosystem {}

impl Ecosystem for {Ecosystem}Ecosystem {
    fn id(&self) -> &'static str {
        "{ecosystem_id}"
    }

    fn display_name(&self) -> &'static str {
        "{Ecosystem Name}"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["{manifest_filename}"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["{lockfile_filename}"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = parse_{manifest}(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn LockFileProvider>> {
        Some(Arc::new({Ecosystem}LockfileParser))
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    // generate_inlay_hints, generate_hover, generate_code_actions, generate_diagnostics
    // all have default implementations in the Ecosystem trait that delegate to lsp_helpers.
    // Override only if custom behavior is needed.

    fn generate_completions<'a>(
        &'a self,
        _parse_result: &'a dyn ParseResultTrait,
        _position: Position,
        _content: &'a str,
    ) -> BoxFuture<'a, Completions> {
        // `is_incomplete` should stay `false` unless this ecosystem serves
        // completions from a capped/unranked index (see PyPI below) —
        // `Vec<CompletionItem>::into()` covers the common exhaustive-results case.
        Box::pin(async move { Vec::new().into() })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

## Step 7: Implement the Lock File Provider

Create lock file parser in `lockfile.rs`:

```rust
//! Lock file parsing for {Ecosystem}.

use std::path::{Path, PathBuf};

use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use tower_lsp_server::ls_types::Uri;

/// Lock file parser for {Ecosystem}.
pub struct {Ecosystem}LockfileParser;

impl LockFileProvider for {Ecosystem}LockfileParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, &["{lockfile_name}"])
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<ResolvedPackages>> + Send + 'a>> {
        Box::pin(async move {
            let content = tokio::fs::read_to_string(lockfile_path)
                .await
                .map_err(deps_core::DepsError::Io)?;

            parse_lock_content(&content)
        })
    }
}

fn parse_lock_content(content: &str) -> deps_core::error::Result<ResolvedPackages> {
    let mut packages = ResolvedPackages::new();

    // TODO: Parse lock file and call packages.insert(ResolvedPackage { ... })

    Ok(packages)
}
```

## Step 8: Implement the Formatter

Create the formatter in `formatter.rs`:

```rust
use deps_core::lsp_helpers::EcosystemFormatter;

pub struct {Ecosystem}Formatter;

impl EcosystemFormatter for {Ecosystem}Formatter {
    fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
        // Format version string for use in code action text edits
        format!("\"{}\"", version)
    }

    fn package_url(&self, name: &deps_core::PackageName) -> String {
        format!("https://registry.example.com/packages/{}", name)
    }

    // Optional: lint manifest-declared names against this ecosystem's naming
    // rules. Default is always `Ok(())` — only override to warn on names the
    // ecosystem's own tooling would never accept (see `deps-npm`'s
    // `NpmFormatter` for a full example). Never used as a construction gate:
    // `PackageName::new` stays infallible regardless of this check.
    fn validate_package_name(&self, _name: &str) -> Result<(), deps_core::InvalidPackageName> {
        Ok(())
    }
}
```

## Step 9: Create lib.rs

Expose public API in `lib.rs`:

```rust
//! {Ecosystem} support for deps-lsp.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::{Ecosystem}Ecosystem;
pub use parser::parse_{manifest};
pub use registry::{Ecosystem}Registry;
pub use types::{{Ecosystem}Dependency, {Ecosystem}Version};
```

## Step 10: Register the Ecosystem

In `deps-lsp/src/lib.rs`, add your ecosystem using the macros:

```rust
// 1. Add re-exports using the ecosystem! macro
ecosystem!(
    "{ecosystem_id}",        // Feature flag name
    deps_{ecosystem},        // Crate name
    {Ecosystem}Ecosystem,    // Main ecosystem type
    [
        {Ecosystem}Dependency,
        {Ecosystem}Version,
        {Ecosystem}Registry,
        // ... other public types
    ]
);

// 2. Add registration in register_ecosystems() using the register! macro
pub fn register_ecosystems(registry: &EcosystemRegistry, cache: Arc<HttpCache>) {
    register!("cargo", CargoEcosystem, registry, &cache);
    register!("npm", NpmEcosystem, registry, &cache);
    register!("pypi", PypiEcosystem, registry, &cache);
    register!("go", GoEcosystem, registry, &cache);
    register!("bundler", BundlerEcosystem, registry, &cache);
    register!("dart", DartEcosystem, registry, &cache);
    register!("maven", MavenEcosystem, registry, &cache);
    register!("gradle", GradleEcosystem, registry, &cache);

    // Add your ecosystem here:
    register!("{ecosystem_id}", {Ecosystem}Ecosystem, registry, &cache);
}
```

The macros handle feature-gating automatically. When the feature is disabled, both the re-exports and registration are compiled out.

## Step 11: Add Tests

Create comprehensive tests co-located with each module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        Uri::from_str("file:///test/{manifest_file}").unwrap()
    }

    #[test]
    fn test_parse_simple_dependencies() {
        let content = r#"..."#;
        let result = parse_{manifest}(content, &test_uri()).unwrap();
        assert!(!result.dependencies.is_empty());
    }

    #[test]
    fn test_position_tracking() {
        let content = r#"..."#;
        let result = parse_{manifest}(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Verify positions are correct
        assert!(dep.name_range.start.line > 0);
        assert!(dep.version_range.is_some());
    }

    #[tokio::test]
    async fn test_ecosystem_trait() {
        let cache = Arc::new(HttpCache::new());
        let ecosystem = {Ecosystem}Ecosystem::new(cache);

        assert_eq!(ecosystem.id(), "{ecosystem_id}");
        assert!(ecosystem.manifest_filenames().contains(&"{manifest_file}"));
    }
}
```

## Checklist

Before submitting a PR for a new ecosystem:

- [ ] Error types with conversions to `deps_core::DepsError`
- [ ] Types implementing `Dependency` and `Version` traits (with `source()` method)
- [ ] Parser with accurate position tracking for names AND versions
- [ ] Lock file parser implementing `LockFileProvider` trait (`locate_lockfile` + `parse_lockfile`)
- [ ] Formatter implementing `EcosystemFormatter` trait (`format_version_for_text_edit` + `package_url`)
- [ ] Registry client implementing `deps_core::Registry` trait with BoxFuture signatures
- [ ] Ecosystem impl with `impl deps_core::ecosystem::private::Sealed` block
- [ ] Unit tests for parser edge cases
- [ ] Integration tests for registry (can be `#[ignore]`)
- [ ] Documentation in lib.rs with examples
- [ ] Added to workspace members in root Cargo.toml
- [ ] Feature flag added in deps-lsp/Cargo.toml
- [ ] Re-exports via `ecosystem!()` macro in deps-lsp/src/lib.rs
- [ ] Registration via `register!()` macro in deps-lsp/src/lib.rs

## Reference Implementations

See existing implementations for reference:
- `crates/deps-cargo/` - Rust/Cargo.toml with crates.io sparse index
- `crates/deps-npm/` - JavaScript/package.json with npm registry
- `crates/deps-pypi/` - Python/pyproject.toml/poetry/requirements.txt with PyPI API and PEP 508 marker support
- `crates/deps-go/` - Go/go.mod with proxy.golang.org
- `crates/deps-bundler/` - Ruby/Gemfile with RubyGems API
- `crates/deps-dart/` - Dart/pubspec.yaml with pub.dev API
- `crates/deps-maven/` - Java/pom.xml with Maven Central (CDN metadata + Solr search)
- `crates/deps-gradle/` - Kotlin/Groovy with version catalogs and property resolution
- `crates/deps-composer/` - PHP/composer.json with Packagist V2 API
- `crates/deps-swift/` - Swift/Package.swift with GitHub API support
- `crates/deps-nuget/` - C#/.NET/.csproj/packages.config with NuGet V3 registry (SemVer2 prerelease, central package management)
- `crates/deps-deno/` - Deno/deno.json with the JSR API, delegating `npm:` specifiers to `deps-npm`'s registry client — the reference implementation for an ecosystem that dispatches across two registries from one manifest

## Key API Contracts

### No async_trait

All trait methods use `BoxFuture` instead of `#[async_trait]`:

```rust
// Correct
fn parse_manifest<'a>(
    &'a self,
    content: &'a str,
    uri: &'a Uri,
) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResult>>> {
    Box::pin(async move { ... })
}

// Wrong — do not use
#[async_trait]
async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResult>> { ... }
```

### Position Tracking

Use `deps_core::lsp_helpers::LineOffsetTable` for byte offset to LSP position conversion:

```rust
use deps_core::lsp_helpers::LineOffsetTable;

let table = LineOffsetTable::new(content);
let position = table.byte_offset_to_position(content, byte_offset);
```

### LockFileProvider Signatures

```rust
impl LockFileProvider for MyLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> { ... }
    fn parse_lockfile<'a>(&'a self, lockfile_path: &'a Path)
        -> Pin<Box<dyn Future<Output = Result<ResolvedPackages>> + Send + 'a>> { ... }
}
```

## Templates

Use the templates in `templates/deps-ecosystem/` as a starting point for new ecosystems.

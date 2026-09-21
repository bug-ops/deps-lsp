# NuGet

## Basics

NuGet is the ecosystem with the most manifest formats `deps-lsp` supports in one place —
`deps-nuget` recognizes all of them:

- **`.csproj`/`.fsproj`/`.vbproj`** (SDK-style project files) — modern `<PackageReference
  Include="..." Version="..." />` entries, in either attribute form or nested-element form
  (`<PackageReference Include="..."><Version>...</Version></PackageReference>`).
- **`Directory.Packages.props`** — .NET's **Central Package Management** file: a single
  `<PackageVersion Include="..." Version="..." />` list shared across every project in a
  repository, with individual `.csproj` files' `<PackageReference>` entries then referencing
  packages by name only (no version).
- **`packages.config`** — the legacy (pre-`PackageReference`) manifest format, still found in
  older .NET Framework projects; its `version="..."` attribute is an exact pin (unlike a bare
  `PackageReference` `Version`'s floor semantics), normalized internally to a bracketed
  `[1.0.0]` range so the same interval parser handles both forms.

```xml
<ItemGroup>
  <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
</ItemGroup>
```

Every dependency resolves against **nuget.org**'s V3 API (`api.nuget.org/v3/index.json`, a
service-index indirection that then points at further per-capability resource URLs — see
below) by default, unless a `NuGet.Config` redirects it to a private feed (see "Private/Custom
Feeds"). When a `packages.lock.json` (or per-project `packages.<name>.lock.json`) file is
present, it is read to resolve each dependency's in-use version. NuGet versions follow
`Major.Minor.Patch[.Revision]` (1–4 numeric components) with SemVer2 prerelease precedence,
compared case-insensitively — no maintained Rust crate implements this scheme, so `deps-nuget`
hand-rolls its own comparator (the same pattern `deps-maven` uses for Maven's own scheme).

## Private/Custom Feeds

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

**Authentication (issue #561)**: a **user-profile-tier** `NuGet.Config`
(Windows `%APPDATA%\NuGet\NuGet.Config`; Unix `$XDG_CONFIG_HOME/NuGet/NuGet.Config`
if set, else `~/.config/NuGet/NuGet.Config`, else `~/.nuget/NuGet/NuGet.Config` —
the first-existing candidate, never merged) is now discovered once at server
start and its `<packageSourceCredentials>` `ClearTextPassword`/`Username`
values are parsed and expanded (`%ENV_VAR%` syntax, re-evaluated on every
resolve so rotating the variable's value takes effect without a file edit). A
credential declared there under key `K` attaches as a `Basic` `Authorization`
header to a repo-declared source **only when all of**: the repo entry's own
key overlaps exactly one user-profile credential; that credential's key
overlaps exactly one user-profile `<add>`; and the repo entry's URL is
**byte-identical** to that `<add>`'s URL (origin-level matching is
deliberately not enough — see below). Any partial match — same key, different
URL; an ambiguous double-match; a `%ENV_VAR%` that is unset; a DPAPI-encrypted
`<Password>` — fails the source closed exactly like an unauthenticated
credentialed source always has, **never** queried anonymously. A repo-tier
`<packageSourceCredentials>` block still forces the same unconditional
fail-closed behavior as before this feature, regardless of any user-profile
match.

Why full-URL equality, not origin equality: `pkgs.dev.azure.com` and
`nuget.pkg.github.com` are shared by every tenant/organization on that host. A
hostile repository could otherwise declare its *own* project's URL under the
same `key` your user profile trusts and receive your PAT on a same-origin,
different-project request. Requiring the exact URL closes that; it also means
the credential is never sent anywhere off the declared feed's origin, even
via a redirect a compromised or misconfigured service index tries to induce.

A credential named for the real `api.nuget.org` (e.g. an Azure-Artifacts
upstreaming setup) never forces a source closed and never attaches — that
lookup was already unauthenticated before this feature and stays that way,
since it is not the leak this feature closes (see "Corrections" below).

**`registries.nuget_user_profile_sources`** (default `false`): with the
setting off, a user-profile file contributes **credentials only** — its own
`<clear/>`/`<remove>`/`<disabledPackageSources>`/`<packageSourceMapping>`
reach no project, and a user-profile-only `<add>` (nothing in the repo names
it) is inert. Turning it on additionally makes such an `<add>` a routing hop
— covering the common `dotnet nuget add source` workflow with no
repo-committed `NuGet.Config` — at the cost of downgrading every dependency
resolved through it to `AlternateRegistry` (OSV/deps.dev/hover-trust
suppressed, same tradeoff any private feed already carries). A
`<disabledPackageSources>` entry in your own profile still withholds your
credential from a matching repo-declared source even with the setting off —
it only ever suppresses the credential, never machine-wide-disables that
source for other projects.

**Fail-closed on misconfiguration**: an invalid feed URL (non-https, userinfo,
malformed, a local/UNC filesystem path, or `protocolVersion="2"`) shows no
version data if it is the only remaining viable source, or is dropped (with a
logged warning) if other valid sources remain. A `<clear/>` that removes every
source down to zero — with or without an invalid entry left to name — is an
explicit fail-closed state, never a silent fallback to `api.nuget.org` (the
same issue #248/#502/#513 regression class Cargo/npm/PyPI already closed).

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented in [Cargo](cargo.md#customprivate-registries). Additionally,
a workspace-declared feed's own service-index resource URLs
(`PackageBaseAddress`/`SearchQueryService`/`RegistrationsBaseUrl`) are
re-validated against this same policy before being trusted — NuGet's service
index is a two-hop indirection (a top-level feed URL resolves to a JSON
document naming further per-capability resource URLs) with no equivalent in
Cargo's/npm's/PyPI's single-URL registry model, so a validated top-level host
could otherwise redirect resolution to an internal host via its own service
index.

**Corrections (issue #561/#562)**: two limitations previously listed here are
now closed, not accepted risk:
- A workspace-declared/alternate feed's flat-container, service-index, and
  registration-hive fetches now go through an origin-pinned,
  connect-address-guarded transport — a redirect off the resolved
  `PackageBaseAddress`/`RegistrationsBaseUrl` to a different host is stopped,
  matching the guarantee `api.nuget.org` itself already had. Registration-hive
  enrichment (publish-time freshness, the hover-only `*(unlisted)*` marker) is
  no longer skipped for these feeds.
- **Wording fix, not a new claim**: the FR-008 public-index carve-out (a
  user-profile credential named for `nuget.org` never forces a source
  closed) is *not* a claim that querying `api.nuget.org` by package name is
  leak-free — it already leaks the name to Microsoft, which is the exact
  leak class #561 exists to close for a genuinely private feed. The
  carve-out exists only because `deps-lsp` already performs this
  unauthenticated public-index lookup today, and this feature must not
  regress that already-shipped behavior. A user who wants the public index
  itself treated as private should not declare it in `<packageSources>`.

**Known limitations**:
- Editing `NuGet.Config` does not take effect until the affected manifest is
  next reparsed — no dedicated file watcher. A user-profile config created
  after server start is picked up only on restart (discovered once, not
  re-walked per parse). Flipping `registries.nuget_user_profile_sources` via
  `workspace/didChangeConfiguration`, in contrast, re-parses already-open
  manifests immediately and purges an already-registered `AlternateRegistry`
  chain (issue #592) — only a direct `NuGet.Config` file edit still needs a
  reparse to be picked up.
- `<packageSourceMapping><clear/>` is not honored — mapping rules only ever
  accumulate across the ancestor chain, never reset, even by a leaf file's own
  `<clear/>` inside that element. Deliberate: undoing the merge-not-nearest-wins
  fix for this one element needs its own empirical verification against real
  NuGet first.
- Authentication is user-profile-tier only (see above) — a repo-tier
  `NuGet.Config` can never carry a credential, even opt-in: a cloned
  repository controls both the credential-shaped value and the destination
  URL it would be sent to, an arbitrary-secret-exfiltration primitive no
  settings key can safely gate.
- DPAPI-encrypted `<Password>` values are permanently out of scope
  (Windows-only, not portably decryptable) — rejected at parse time, never
  silently dropped.
- The machine-wide config tier (`/etc/opt/NuGet/Config`,
  `%ProgramFiles(x86)%\NuGet\Config`) is not read — explicit non-goal, same
  cut as the user-profile-vs-repo boundary above.
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

## Release-Freshness Coverage

NuGet's freshness signal (gated by `freshness.enabled`, default `true`) works, but **only for
the newest ~8 versions of a package** — for any feed that exposes a `RegistrationsBaseUrl`
resource in its service index (nuget.org always does), ages come from walking the registration
hive's pages backwards from the newest, stopping once enough recent versions are covered. This
is a deliberate MVP trade-off, not an oversight: completion filters by the typed prefix
*before* truncating to the versions it renders, so a prefix that selects only older versions
(e.g. typing `6.` against a package whose newest release is `9.x`) renders those versions with
no age at all, even though hover on the same package shows ages normally (hover only ever
renders the newest ~8 anyway). A private V3 feed (Azure Artifacts, BaGet, GitHub Packages) that
omits `RegistrationsBaseUrl` entirely degrades to `published_at: None` for every version, with
the version list itself unaffected. Unlisted versions (the registration hive's `1900-01-01`
sentinel date) never render a bogus age. Added cost is typically zero extra round trips (the
version list and the registration index are fetched concurrently), one extra round trip when a
package's registration hive externalizes its last page.

See [npm](npm.md#release-freshness-coverage) for the other half of this shared signal — the two
ecosystems pay for freshness in very different ways.

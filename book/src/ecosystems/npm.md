# npm

## Custom/Private Registries

An npm dependency whose scope (via `@scope:registry=`) or whose workspace (via a
top-level `registry=` override) resolves to a private/custom registry through
`.npmrc` gets the same hover/diagnostic/completion value a `registry.npmjs.org`
dependency gets — instead of showing no version data, or (before this feature)
silently checking the wrong (public) registry.

**Resolution**: `.npmrc` is read from a two-tier hierarchy — the project tier
(walked from the opened `package.json`'s directory up to the filesystem root,
closest directory winning; a deliberate superset of npm's own project-root-only
read, chosen for monorepo ergonomics and mirroring Cargo's `.cargo/config.toml`
discovery — see [Cargo](cargo.md#customprivate-registries)) and the user tier
(`~/.npmrc`). The global tier (`$PREFIX/etc/npmrc`) is not read. A
`@scope:registry=` entry always takes precedence over a top-level `registry=`
override for a dependency in that scope. Scope keys are matched byte-exact, with
no case folding, matching npm's own lookup. A `${VAR}`-style placeholder in
either key's value is expanded from this LSP server's own process environment;
an undefined variable makes the whole entry invalid (same outcome as an invalid
URL, below). `deps-lsp` watches `.npmrc` for external changes (e.g. a `git
checkout`) and reparses every open `package.json` to refresh pushed
diagnostics, rather than waiting for that document's own next edit.

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
setting documented in [Cargo](cargo.md#customprivate-registries) — unlike
Cargo's `$CARGO_HOME`-is-trusted split, npm's project and user `.npmrc` tiers
are policy-*symmetric*: phase 1 has no credential provenance to protect, so
there is no tier that is "the user's own configuration" in the way
`$CARGO_HOME` is for Cargo. Setting `registries.workspace_registries` to
`"all"` for npm's benefit also widens it for Cargo, and vice versa.

**Known limitations**:
- Package-*name* completion (typing a brand-new dependency) always searches
  `registry.npmjs.org`, even for a scope resolved to a private registry — the
  string being searched is a prefix the user typed into the name field, not a
  resolved private dependency name, so this is safe but not registry-aware.
- A dependency resolved to a private registry drops out of OSV vulnerability
  scanning and loses its npmjs.com hover link (an advisory or link keyed to the
  public package name does not apply to a same-named private package) and its
  relative-age ("published N days ago") hover suffix.
- `.yarnrc`/`.yarnrc.yml` (Yarn Berry's own config format) are not read; a
  standard `.npmrc` present in the workspace is still honored either way.
  pnpm's own `pnpm-workspace.yaml` catalog extension *is* read — see below.

## Non-Registry Dependency Sources

A dependency declared against a git repository, a local filesystem path, or a workspace
sibling is classified as such instead of defaulting to `registry.npmjs.org` — this covers
`git+ssh://`/`git+https://`/`git://` URLs, a bare HTTPS URL to a known git host
(GitHub/GitLab/Bitbucket) ending in `.git`, `github:`/`gitlab:`/`bitbucket:`/`gist:`
shorthand (`owner/repo[#ref]`), a direct tarball URL, `file:`/`link:`/`portal:`-prefixed and
bare local paths (`./`, `../`, `~/`, or a Windows drive letter), and `workspace:` protocol
dependencies. A dependency resolved this way is never sent to the registry, drops its
public-registry hover link, and is excluded from OSV vulnerability scanning against the
public package name — matching the treatment Cargo already gives a `git =`/`path =`
dependency (resolves #1202).

## `npm:` Alias Resolution

npm/pnpm/yarn let a `package.json` dependency install under a different local
import name than its registry package, via the `npm:` protocol prefix:
`"my-react": "npm:react@^18.0.0"` — `my-react` is the local key, `react` is the
real package to resolve, `^18.0.0` is its version requirement. Hover,
completion, diagnostics, code lens, inlay hints, `.npmrc` scoped-registry
routing, and OSV vulnerability lookups all resolve against the real package
name (`react`), while the local alias key stays the position anchor for
hover/diagnostic ranges in the editor (resolves #654). A scoped real package
name (`"my-pkg": "npm:@scope/pkg@^1.0.0"`) is supported the same way. A
dist-tag alias (`"npm:react@beta"`) or one with no version at all
(`"npm:react"`) resolves as an existence check (equivalent to a bare `"*"`
requirement) rather than a specific version comparison.

**Code actions/lens are not offered** for an `npm:`-aliased dependency: the
manifest text at the version position is the whole `npm:pkg@range` literal,
not just the range, so an automated rewrite would need to preserve the alias
prefix — not yet implemented. This is a deliberate, safe degradation (no
version data is lost, only the one-click fix), not a bug.

**Known limitation**: the pnpm-catalog combination form
(`npm:<pkg>@catalog:<name>`) is not detected — see pnpm Catalogs below.

## pnpm Catalogs

A `package.json` dependency declared as `"catalog:"` (the default catalog) or
`"catalog:<name>"` (a named catalog) resolves against the nearest-ancestor
`pnpm-workspace.yaml`'s `catalog:`/`catalogs.<name>:` map — the same
hover/diagnostic/completion/inlay-hint experience a literal semver range gets,
instead of an unresolvable raw string.

**Resolution**: the nearest `pnpm-workspace.yaml` found walking up from the
`package.json`'s directory wins (matching pnpm's own `find-workspace-dir`
single-root-per-tree behavior — nested/multiple workspace roots are not
searched further). `catalog:` and `catalog:default` are equivalent references
to the default catalog, which may be defined either as a top-level `catalog:`
block or a `catalogs.default:` section (but never both — see below). `deps-lsp`
watches `pnpm-workspace.yaml` for external changes and reparses every open
`package.json` to refresh pushed diagnostics, rather than waiting for that
document's own next edit.

**Fail-closed, never destructive**: whenever a `catalog:` specifier does not
resolve to a parseable semver range — no `pnpm-workspace.yaml` found, the file
is malformed, the referenced catalog or entry doesn't exist, or the entry's
value isn't a semver range (`workspace:*`, a git URL) — the dependency's
version *requirement* is left unset while hover still renders an explanatory
message. This is a deliberate correctness guarantee, not a missing feature: an
unresolved catalog specifier must never be treated as a valid semver range,
since that would let the "Update all outdated dependencies" quick-fix silently
overwrite `"react": "catalog:"` with a literal version, destroying the catalog
reference.

**Both a top-level `catalog:` block and a `catalogs.default:` section present**
is treated as unresolvable for *every* `catalog:` specifier in the workspace
(not only default-catalog references) — matching pnpm's own
`checkDefaultCatalogIsDefinedOnce`, which rejects the whole workspace manifest
in this situation before returning any catalog map at all; this deliberately
never per-key-merges the two sections.

**Known limitations**:
- The `npm:<pkg>@catalog:<name>` combination form (an `npm:` alias whose
  version is itself a catalog reference) is not detected — the base `npm:`
  alias form (no catalog combination) *is* resolved, see `npm:` Alias
  Resolution above.
- A catalog entry whose value isn't a scalar string (e.g. a nested mapping)
  gets its own distinct "not a version string" message rather than being
  validated against pnpm's own schema further.
- `yarn.lock` and `bun.lock` are not read for in-use/resolved-version
  detection — only `package-lock.json` and `pnpm-lock.yaml` are supported
  lock file formats (tracked as follow-ups on issue #709).
- `pnpm-lock.yaml`'s `importers` map is aggregated flatly across every
  workspace member into one shared version pool per package name, without
  correlating an importer entry back to the specific `package.json` being
  queried (spec 052's deliberate scoping). When two importers have
  *overlapping* semver ranges that pnpm resolved to *different* concrete
  versions, hover/OSV scanning for one importer's `package.json` can show the
  version resolved for a different importer instead of its own — a
  false-negative risk for vulnerability scanning, not just an imprecision.
  The same applies to any `package.json` under the workspace root that isn't
  itself a registered importer: it inherits whichever importer's version the
  ancestor lock file search happens to attach to.

## Package Name Validation

When a dependency in `package.json` fails to resolve against the npm registry, the diagnostic distinguishes between two cases instead of always reporting "Unknown package":

- **`Invalid package name '<name>': <reason>`** — the name itself violates npm's own naming rules (e.g. it starts with `.`/`_`, exceeds 214 characters, contains a character outside npm's URL-friendly set, or is a reserved name like `node_modules`).
- **`Unknown package '<name>'`** — the name is syntactically valid but was not found in the registry (typo, private/unpublished package, etc.).

The check is deliberately permissive: uppercase names are still accepted (npm only warns on those for legacy packages, never rejects), and it accepts every character npm's own `encodeURIComponent(segment) === segment` predicate accepts, including `! ' ( ) * - . _ ~` — not just alphanumerics and hyphens.

## Release-Freshness Coverage

npm's freshness signal (gated by `freshness.enabled`, default `true`) issues an **entire
additional full-packument fetch** per package, not a marginal delta — the abbreviated
packument `get_versions` already fetches carries no publish dates, so freshness attaches a
separately-fetched, TTL'd (1 hour) `{version: date}` map derived from the full packument's
`time` field instead. npm is the one ecosystem in this project where `freshness.enabled:
false` genuinely removes a whole request per hover/completion round, not just a conditional
revalidation. See [NuGet](nuget.md#release-freshness-coverage) for the other half of this
shared signal.

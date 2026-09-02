---
aliases:
  - npm .npmrc Registry Support
  - npm Scoped Registry Resolution
tags:
  - sdd
  - spec
  - research
  - enhancement
  - npm
  - security
created: 2026-09-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
---

# Feature: npm `.npmrc` Custom/Private Registry Support (Scoped Registries)

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Issue**: #502
> **Branch**: feat/502-npm-npmrc-registry-support
> **Priority**: P3
> **Type**: research/enhancement
> **Revision**: r3 — in sync with [[plan]] r3. FR-006/NFR-002's loopback rule
> corrected (the `http` carve-out is `cfg(test)`/`test-util`-only, not a
> release-build exception) and FR-010 now pins the unregistered-alternate
> fetch path. See [[plan#12. Critic Finding Disposition|plan §12]] (N-C1, N-S1).

## 1. Overview

### Problem Statement

`deps-npm` has zero support for `.npmrc`-declared custom or private
registries — confirmed live this session:

- `grep -rl "npmrc" crates/deps-npm/src/` returns zero hits.
- `crates/deps-npm/src/registry.rs:20` hardcodes
  `const REGISTRY_BASE: &str = "https://registry.npmjs.org";` with no
  per-dependency or per-scope registry resolution anywhere in the crate.
- Every npm package — regardless of any `.npmrc` present in the
  workspace, the user's home directory, or the process environment —
  is hovered, completed, and diagnosed against the public registry.

This is silently wrong, not merely incomplete: for any workspace using an
enterprise npm proxy, a GitHub Packages scoped registry
(`@myorg:registry=https://npm.pkg.github.com/`), a Verdaccio instance, or
an Artifactory npm repo, the LSP reports version data for the *wrong*
registry with no indication anything is off — the same silent-wrong-data
bug class issue #248 fixed for Cargo (`CustomRegistry` dependencies were
resolved against the public registry instead of the configured private
one).

`deps-cargo` already ships a proven, tested reference pattern for exactly
this class of problem — see [[023-cargo-custom-registries/spec|023]]
(issues/PRs #431/#440/#441/#443/#447, SSRF hardening #449/#453/#457/#460):
parser resolves an alias to a concrete index URL → `EcosystemFormatter`
gates on whether that source is resolvable → the ecosystem's `Registry`
impl routes the fetch to the right index → an unresolved/misconfigured
alias fails closed (no data), never silently falling back to the public
registry. Much of that pattern is now *generic* infrastructure already
sitting in `deps-core`, added specifically so later ecosystems would not
have to reinvent it:

- `DependencySource::AlternateRegistry { index, mirrors_crates_io }`
  (`crates/deps-core/src/parser.rs:882-899`) is a source-agnostic "resolved
  to a concrete, fetchable index URL" variant — `deps-npm` can construct it
  directly, no `deps-core` change needed for this piece.
- `Registry::get_versions_from` / `get_latest_matching_from`
  (`crates/deps-core/src/registry.rs:132,212`) are defaulted trait methods
  any `Registry` impl can override — `deps-npm`'s registry client would
  override these exactly as `CargoRegistry` does, again with zero
  `deps-core` change required.
- `EcosystemFormatter::can_resolve_source` (added by #440's FR-016,
  defaulted to `DependencySource::is_version_resolvable()`) is the single
  override point gating hover/diagnostics/code-actions — `NpmFormatter`
  would override it exactly as `CargoFormatter` does.
- `deps_core::net_policy` (`HostClass`, `classify_host`,
  `RegistryAccessPolicy`, `WorkspaceRegistryAccess`) is the SSRF-hardening
  host classifier already gating Cargo's workspace-declared registries
  behind a `cargo.workspace_registries` setting (`off`/`public_only`/`all`,
  default `public_only`) — npm reuses that *same* setting rather than adding
  a parallel one, since `HttpCache` holds exactly one global
  `Arc<RegistryAccessPolicy>`; the key is renamed to
  `registries.workspace_registries` to match its real, all-ecosystem scope
  (FR-008, resolved in [[plan#Key Design Decisions\|plan]]).
- `DependencySource::CustomRegistry { url }`
  (`crates/deps-core/src/parser.rs:875-882`) is the existing "present, but not
  resolved to a concrete index this LSP can query" state —
  `is_version_resolvable()` is already `false` for it — which is exactly
  npm's FR-006 fail-closed outcome, again with no `deps-core` change.

What `deps-npm` needs on top of that shared foundation is npm-specific:
parsing `.npmrc`'s INI-like format, npm's config-file precedence order,
and — the one piece with no Cargo analogue — **scoped-registry
resolution** (`@scope:registry=`), where the registry a dependency
resolves against depends on a prefix of the package *name* itself, not on
an explicit per-dependency field the manifest declares (Cargo's
`registry = "my-corp"` is always explicit on the dependency; npm's scope
routing is implicit and keyed off the `@scope/` name prefix, which
`deps-npm`'s parser already extracts — see
`crates/deps-npm/src/parser.rs`'s `test_scoped_package`, confirming scoped
names like `@vitest/coverage-v8` already parse correctly today, just with
no scope-aware registry lookup on top).

Competitive pressure for this specific gap is concrete and ecosystem-
specific: Dependi's private-registry support is a paid Pro feature, and 6
of Dependi's 17 open GitHub issues are private-registry requests —
`` github.com/filllabs/dependi/issues/211 ``, `` .../214 ``, `` .../285 ``,
`` .../292 ``, `` .../293 ``, `` .../18 ``. Of the six ecosystems the
competitive-parity playbook
(`.local/testing/playbooks/competitive-parity.md`, "Private/alternative
registry support" row) names as still-unfiled Cargo-pattern follow-ons —
Maven `settings.xml`, NuGet feeds/`NuGet.Config`, pip `extra-index-url`,
`GOPROXY`, Composer `repositories`, Bundler `source` — npm is the
highest-value pick: most cited competitive demand, and the only one of the
six with genuinely novel (scope-keyed, not alias-keyed) resolution
semantics worth spec'ing on its own.

`gh issue list` / `gh issue list --search` found no existing open or
closed issue for npm `.npmrc` registry support in this repository —
confirmed unfiled this session.

> [!warning] Assumptions
> - Target registries speak the same npm-registry-protocol packument JSON
>   `deps-npm` already parses (abbreviated or full) — Verdaccio, Artifactory
>   npm-remote, GitHub Packages npm registry, and Azure Artifacts npm feeds
>   all implement this. A registry that does not (a bespoke internal proxy
>   with a non-standard response shape) is out of scope, matching how
>   Cargo's spec scoped out non-sparse-index registries.
> - `.npmrc` files are plain INI-style `key=value` (or `key = value`) lines,
>   `#`/`;`-prefixed comments, and npm's flat namespacing for scoped keys
>   (`@scope:registry=...`, `//host/path/:_authToken=...`) — no nested TOML
>   or YAML structure to parse, unlike Cargo's `.cargo/config.toml`.
> - **Divergent from Cargo's trust model, and load-bearing for this spec's
>   design**: npm's own documented convention is that a *project-root*
>   `.npmrc` legitimately carries an env-var-interpolated auth line
>   (`//registry.example.com/:_authToken=${NPM_TOKEN}`) and is routinely
>   committed to the repository — unlike Cargo, where a workspace file is
>   never expected to carry a credential at all. Cargo's FR-009 rule ("auth
>   is populated only when the index URL provenance is
>   `$CARGO_HOME`-declared, never a workspace file") does not translate
>   cleanly to npm's ecosystem convention. See Open Questions.

### Goal

An npm dependency whose name (via `@scope:registry=`) or whose workspace
(via a top-level `registry=` override) resolves to a private/custom
registry through `.npmrc` gets the same hover/diagnostic/completion value
a `registry.npmjs.org` dependency gets today — with zero regression for
workspaces that declare no custom registry, and with no credential
transmitted to any registry in this phase (auth wiring deferred, see Out
of Scope).

### Out of Scope

> [!danger] Explicit Exclusions
> - **All auth wiring** — `_authToken`, `_auth`, `_password`, `_authIdent`,
>   `always-auth`. Phase 1 resolves *which* registry a dependency belongs
>   to and fetches it unauthenticated; it never reads, stores, or transmits
>   any of these keys. This mirrors how Cargo's own implementation treated
>   auth as the single most security-sensitive sub-problem — but here it is
>   scoped out of phase 1 entirely rather than solved in the same PR,
>   because (per the Assumptions callout above) npm's project-`.npmrc`
>   convention does not cleanly fit Cargo's "credential only from a
>   user/global-scoped file" trust rule. A follow-up spec should resolve
>   this deliberately rather than inherit Cargo's rule by default.
> - **`.yarnrc` / `.yarnrc.yml`** (Yarn Classic / Yarn Berry's own,
>   differently-shaped config format, including Yarn Berry's
>   `npmScopes`/`npmRegistryServer` keys) — a distinct file format from
>   `.npmrc`, not addressed here even though Yarn workspaces are common.
>   Yarn Classic without a `.yarnrc` override does read `.npmrc`, so it is
>   covered incidentally; a genuine `.yarnrc[.yml]` parser is a separate
>   follow-up.
> - **pnpm-specific config** (`pnpm-workspace.yaml` catalog/registry
>   settings) — pnpm reads standard `.npmrc` for registry config, so is
>   covered incidentally by this spec; pnpm-only extensions are not.
> - **The global npm config tier** (`$PREFIX/etc/npmrc`, i.e. the
>   Node.js-installation-wide config) — project + user tiers cover the
>   overwhelming majority of real private-registry setups; global-tier
>   resolution requires locating the active Node/npm installation prefix,
>   which this LSP has no existing mechanism for and is not worth building
>   for a P3 item. See FR-014.
> - **Private package *name* search/completion** for a registry that does
>   not implement npm's `-/v1/search` endpoint shape — unlike Cargo's
>   sparse-index protocol, this is not universally absent for private npm
>   registries (Verdaccio and Artifactory both implement a compatible
>   search endpoint), so this exclusion is narrower: only registries that
>   don't serve it get a no-op, not every alternate registry unconditionally
>   (contrast Cargo's FR-001, where search is unconditionally unreachable
>   for every alternate source).
> - **A dedicated `.npmrc` file watcher** — same choice Cargo's FR-013
>   made: document the staleness limitation (edits take effect on next
>   reparse of the affected `package.json`) rather than build a new watcher
>   subsystem.

## 2. User Stories

### US-001: Scoped private-registry version resolution

AS A developer with a dependency on a GitHub Packages scoped registry
I WANT hover, diagnostics, and completion to work for it
SO THAT I get the same LSP value I get for public npm dependencies

**Acceptance criteria:**
```
GIVEN a package.json with "@myorg/internal-lib": "^2.0.0"
  AND a .npmrc with @myorg:registry=https://npm.pkg.github.com/
WHEN I hover over the @myorg/internal-lib dependency
THEN the hover shows the latest version available on
     npm.pkg.github.com, not registry.npmjs.org, and no request is
     sent to registry.npmjs.org for "@myorg/internal-lib"
```

### US-002: Full-mirror resolution via top-level `registry=`

AS A developer whose company routes all npm traffic through a corporate
proxy (Artifactory/Verdaccio)
I WANT unscoped dependencies to resolve against that proxy
SO THAT hover/diagnostics reflect what my proxy actually serves (which
may lag or diverge from the public registry)

**Acceptance criteria:**
```
GIVEN a .npmrc with registry=https://npm.mycorp.example/
WHEN I hover over any unscoped dependency
THEN the hover reflects npm.mycorp.example's data, not
     registry.npmjs.org's
```

### US-003: No regression for public-only workspaces

AS A developer with no `.npmrc` in my workspace or home directory
I WANT the LSP to keep behaving exactly as it does today
SO THAT this feature introduces zero risk for the overwhelming majority
of npm workspaces

**Acceptance criteria:**
```
GIVEN no .npmrc exists at any resolvable tier
WHEN I hover over any dependency
THEN the hover is byte-identical to pre-feature behavior
     (registry.npmjs.org)
```

### US-004: Unresolved/misconfigured registry fails closed

AS A developer whose `@scope:registry=` entry points at an unreachable or
invalid URL
I WANT the LSP to show no data for that scope rather than silently
checking the public registry
SO THAT I never mistake a stale/wrong public-registry result for my
private registry's actual state

**Acceptance criteria:**
```
GIVEN @myorg:registry=not-a-valid-url in .npmrc
WHEN I hover over an @myorg/* dependency
THEN no version data is shown, and no request is sent to
     registry.npmjs.org for that dependency (mirrors the exact
     regression class issue #248 fixed for Cargo)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL parse `.npmrc` files using npm's documented `key=value` / `key = value` INI-like grammar, treating `#` and `;` as full-line comment markers and ignoring blank lines | must |
| FR-002 | THE SYSTEM SHALL merge `.npmrc` tiers in npm's own precedence order: project (`./.npmrc`, walked from the `package.json` directory) overrides user (`~/.npmrc`) overrides the built-in default (`registry.npmjs.org`) — global tier (`$PREFIX/etc/npmrc`) is explicitly out of scope (see Out of Scope) | must |
| FR-003 | WHEN the merged config contains a top-level `registry=<url>` key AND the URL passes the same https/no-userinfo validation Cargo's `RegistryIndex` applies THE SYSTEM SHALL represent every unscoped (`Registry`-sourced) dependency's source as `DependencySource::AlternateRegistry { index: <url>, mirrors_crates_io: false }`, reusing the existing `deps-core` variant with no new type needed | must |
| FR-004 | WHEN a dependency's package name has an `@scope/` prefix AND the merged config contains a matching `@scope:registry=<url>` key that passes the same URL validation THE SYSTEM SHALL represent that dependency's source as `DependencySource::AlternateRegistry { index: <url>, mirrors_crates_io: false }`, taking precedence over any top-level `registry=` override for that dependency | must |
| FR-005 | WHEN a scoped dependency has no matching `@scope:registry=` entry AND no top-level `registry=` override resolves THE SYSTEM SHALL fall back to the public default registry — this is npm's normal, common case (an org scope used purely for namespacing, not registry routing) and is explicitly *not* the same situation as FR-006's fail-closed case | must |
| FR-006 | WHEN a `registry=` or `@scope:registry=` value is present but fails URL validation (non-https, contains userinfo, or is not a well-formed URL) or is blocked by FR-008's policy THE SYSTEM SHALL represent that dependency's source as `DependencySource::CustomRegistry { url: <the raw value as written> }` — the existing `deps-core` variant whose `is_version_resolvable()` is already `false` — logging a `tracing::warn!` naming the raw value, and SHALL NOT fetch that dependency's name against the public registry — closes the same regression class as issue #248. The **only** exception to the https requirement is an `http` loopback host (`127.0.0.1`/`localhost`/`::1`), and it is compiled in **only** under `#[cfg(any(test, feature = "test-util"))]`, mirroring both `deps-cargo`'s `is_loopback_url` (`deps-cargo/src/config.rs:185`) and `deps-core`'s `is_loopback_host`/`ensure_https` (`deps-core/src/cache.rs:121,151-160`). In a release build `registry=http://localhost:4873` therefore fails closed to `CustomRegistry` — which is also the only outcome the fetch layer can deliver: `HttpCache::ensure_https` guards every send site on the workspace path, so accepting such a URL here would trade a clean fail-closed warning for an opaque `CacheError` at fetch time. An `https` loopback host is accepted by URL validation in every build and gated by FR-008's policy instead | must |
| FR-007 | WHEN a `registry=` or `@scope:registry=` value contains a `${VAR}` environment-variable placeholder (npm's own `.npmrc` env-interpolation syntax) THE SYSTEM SHALL expand `VAR` from the LSP server's process environment when it is set, then validate the expanded string per FR-006; WHEN `VAR` is not set THE SYSTEM SHALL treat the value as invalid per FR-006, never attempting to fetch the literal `${VAR}`-containing string as a URL. Expansion SHALL apply only to these two registry-URL key shapes — no auth-shaped key is parsed at all (FR-013/NFR-001), so no credential is ever expanded — and the FR-006 warning SHALL log the raw, unexpanded value so a rejected expansion cannot leak an environment variable's contents | must |
| FR-008 | THE SYSTEM SHALL classify every resolved index URL's host through `deps_core::net_policy::classify_host` and gate the fetch behind the shared `registries.workspace_registries` setting (`off` / `public_only` / `all`, default `public_only`), and SHALL route every alternate-registry request through `HttpCache`'s workspace transport so each redirect hop is re-classified, not only the initial URL. This is the setting today named `cargo.workspace_registries`, **renamed** because `HttpCache` holds exactly one global `Arc<RegistryAccessPolicy>`: a separate `npm.*` key would be last-writer-wins against Cargo's and could silently widen its already-shipped SSRF gate. Breaking config change, pre-1.0, no alias — resolved in [[plan#Key Design Decisions\|plan]] | must |
| FR-009 | THE SYSTEM SHALL add `NpmFormatter::can_resolve_source` (overriding the existing defaulted `EcosystemFormatter::can_resolve_source` hook added by #440's FR-016) so hover/diagnostics/code-actions correctly gate on a resolved `AlternateRegistry` source — no `deps-core` trait change required, this hook already exists generically | must |
| FR-010 | THE SYSTEM SHALL add `Registry::get_versions_from` / `get_latest_matching_from` overrides on `deps-npm`'s registry client (structured analogously to `CargoRegistry`'s `alternates: DashMap<...>` map), routing fetches for `AlternateRegistry`-sourced dependencies to the resolved index instead of `REGISTRY_BASE` — reuses the existing defaulted `deps-core::Registry` trait methods, no `deps-core` change required. WHEN an `AlternateRegistry`'s `index` has **no** registered client THE SYSTEM SHALL return `PackageNotFound` and SHALL NOT fall back to the public registry: npm always sets `mirrors_crates_io: false`, so Cargo's mirror-degradation arm (`deps-cargo/src/registry.rs:503,529`) is dead for npm and the unregistered case is unconditionally the error arm. Falling back would send a private package name to `registry.npmjs.org` — the exact FR-006/#248 leak the rest of this spec closes. Registration stays parse-time-only (`parse_manifest`), never lazy on the fetch path, matching Cargo | must |
| FR-011 | WHEN a resolved alternate registry does not implement (or is not known to implement) the `-/v1/search` endpoint shape THE SYSTEM SHALL no-op package-name search/completion for dependencies resolved to it rather than erroring — resolved in [[plan#Key Design Decisions\|plan]]: unconditional no-op, mirroring Cargo's simpler "always unreachable" choice | must |
| FR-012 | THE SYSTEM SHALL memoize `.npmrc` parsing **per `.npmrc` file path**, invalidated by that file's mtime, caching raw unvalidated entries so that URL validation, `${VAR}` expansion and FR-008 policy gating re-run on every parse — resolved in [[plan#Key Design Decisions\|plan]]: a top-level `registry=` override affects every unscoped dependency, so a per-dependency lazy trigger cannot hold; mirrors `deps-cargo`'s `ConfigFileCache` exactly, which is likewise keyed per file path (npm has no workspace-root concept for config discovery — `NpmParseResult::workspace_root()` returns `None` — and neither does Cargo's config cache) | must |
| FR-013 | THE SYSTEM SHALL NOT read, log, or transmit any of `_authToken`, `_auth`, `_password`, `_authIdent`, `always-auth`, or any `//<host>/:_*` scoped-credential key in phase 1 — parsing SHALL skip these keys entirely rather than parse-then-discard, so no code path ever holds a credential value in memory | must — security-blocking |
| FR-014 | THE SYSTEM SHALL resolve user-tier (`~/.npmrc`) config discovery via the `dirs` crate's `home_dir()` — resolved in [[plan#Key Design Decisions\|plan]]: a deliberate divergence from Cargo's raw-env-var-only precedent, adding the first `dirs`-family dependency to this workspace, because npm's user-tier `.npmrc` is a materially more common private-registry mechanism than Cargo's `$CARGO_HOME` override | must — the choice, not a specific mechanism, is mandatory |
| FR-015 | WHEN the resolved dependency source is not the public registry THE SYSTEM SHALL suppress `NpmFormatter`'s hover heading link to `npmjs.com`, mirroring Cargo's FR-014 (a live-data hover with a public-registry link for a private package reads as false confirmation the link is real) | must |
| FR-016 | THE SYSTEM SHALL document `.npmrc` staleness as a known limitation (edits take effect on the next reparse of the affected `package.json`) rather than add a dedicated file watcher, mirroring Cargo's FR-013 resolution | must — the choice itself, not a specific mechanism, is mandatory |
| FR-017 | WHEN a `CompletionContext::Version`'s bare `package_name` is joined against `parse_result.dependencies()` (entirely inside `deps-npm`'s `generate_completions`, which already receives `parse_result`, so no `deps-core` signature change) THE SYSTEM SHALL route the version fetch to the source that name resolves to: `Registry` (or no match in the manifest) to the public registry unchanged, `AlternateRegistry { index }` to that index's registered client, and `CustomRegistry` — or a name whose occurrences resolve to two or more *different* sources — to **no completions at all** rather than an arbitrary or public-registry lookup. Without this, typing a version for a private `@scope/` dependency sends its name to `registry.npmjs.org`, the same leak class FR-006 closes for hover/diagnostics/code-actions. Mirrors Cargo's FR-012 (`CompletionSource`/`resolve_completion_source`/`alternate_client`), adapted to npm's scope-keyed rather than alias-keyed resolution. Package-*name* completion (FR-011) stays deliberately source-blind: the string sent there is a prefix the user typed into the name field, not a resolved private dependency name | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No auth-shaped `.npmrc` key (`_authToken`, `_auth`, `_password`, `_authIdent`, `always-auth`, scoped `//host/:_*` credentials) is ever parsed, held in memory, logged, or transmitted in phase 1 — verified by a test asserting the parsed config type has no field capable of holding such a value (structural, not just behavioral, per the same pattern Cargo's FR-009/NFR-001 established) |
| NFR-002 | Security | Every resolved index URL is validated (https-only, no userinfo — the sole `http` carve-out is a loopback host under `#[cfg(any(test, feature = "test-util"))]`, matching `deps-cargo`'s `is_loopback_url` and `deps-core`'s `ensure_https`; a release build has no `http` exception at all) and **normalized** (trailing slashes stripped, so `https://x/` and `https://x` are one index rather than two router entries producing a doubled-slash fetch URL) before any network request, using the same validation logic Cargo's `RegistryIndex` newtype applies — resolved in [[plan#Key Design Decisions\|plan]]: a new, minimal `deps-npm`-local `NpmRegistryIndex` newtype, not a promotion of `RegistryIndex` into `deps-core`, since Cargo's type is structurally coupled to an `IndexTrust` concept npm's auth-free phase 1 has no use for |
| NFR-003 | Security | Residual risk, must be stated for security-reviewer sign-off before implementation merges, identical in shape to Cargo's NFR-003: even with NFR-001/002 satisfied, an unauthenticated HTTPS GET to a workspace-declared index still occurs, which is reachability into the user's internal network usable for existence probing by a hostile repository — mitigated identically by `registries.workspace_registries` defaulting to `public_only`. Two divergences from Cargo need explicit sign-off: (a) npm's user-tier `~/.npmrc` is gated by the *same* policy as the project tier, where Cargo treats `$CARGO_HOME` as trusted-by-definition (npm phase 1 has no credential provenance to protect, so its tiers are policy-symmetric); (b) per FR-008 the policy is shared across every ecosystem, so widening it for npm also widens it for Cargo |
| NFR-004 | Performance | No additional filesystem **content** reads for a workspace declaring no `.npmrc` at any tier. `stat` calls are not zero and cannot be: the ancestor walk pays at most one `stat` per ancestor directory (capped at 64, matching `deps-cargo`'s `MAX_CONFIG_ANCESTOR_DEPTH`) plus one for `~/.npmrc`, the same unavoidable cost class as Cargo's `ConfigFileCache` mtime check. Resolved per FR-012 |
| NFR-005 | Reliability | Zero behavior change for any workspace declaring no `.npmrc` — verified by the existing `deps-npm` test suite producing unchanged results (see SC-002 for the one mechanical, signature-only fixture change FR-017 forces) |
| NFR-006 | Maintainability | The scope-vs-toplevel precedence rule (FR-004 over FR-003) is verified by a test asserting a dependency matching both an `@scope:registry=` entry and a top-level `registry=` entry resolves to the scope-specific one |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencySource::AlternateRegistry` | Existing `deps-core` variant (added by #440), reused as-is — the FR-003/FR-004 resolved state | `index: String` (the **normalized** index URL), `mirrors_crates_io: bool` (always `false` for npm — no analogous mirror-verification concept exists in npm's registry protocol) |
| `DependencySource::CustomRegistry` | Existing `deps-core` variant, reused as npm's FR-006 fail-closed state — no new variant and no `deps-npm`-local source enum is introduced | `url: String` — the raw `.npmrc` value as written; `is_version_resolvable()` is already `false`, so every existing fail-closed gate applies unchanged |
| `NpmConfig` | New `deps-npm` type — merged resolved `.npmrc` hierarchy | `registry: Option<Result<NpmRegistryIndex, InvalidEntry>>` (top-level override), `scoped_registries: HashMap<String, Result<NpmRegistryIndex, InvalidEntry>>` keyed by the scope **including** its `@`, byte-exact as written, with no case folding (matching npm's own literal `@${scope}:registry` key lookup) |
| `InvalidEntry` | New `deps-npm` type — a present-but-unusable entry, carrying what FR-006 needs to build `CustomRegistry` and to warn | `raw: String` (as written, never the expanded form), `reason: NpmRegistryIndexError` |
| `NpmRegistryIndex` | Validated, normalized index URL newtype, new and `deps-npm`-local (resolved in [[plan\|plan]] per NFR-002 — not promoted from `deps-cargo`) | https-only (the `http`-loopback carve-out exists only under `cfg(test)`/`test-util`), no userinfo, trailing-slash-normalized, policy-gated, no trust tier |
| `NpmConfigCache` | New `deps-npm` type — per-`.npmrc`-**file-path** memoization (FR-012) | Caches raw entries + mtime, `!=` comparison, capacity 256; mirrors `deps-cargo::config::ConfigFileCache` |
| `NpmParseContext` | New `deps-npm` type — the per-ecosystem shared parse context, mirroring `CargoParseContext` | `policy: Arc<RegistryAccessPolicy>`, `config_cache: Arc<NpmConfigCache>` |
| `NpmRegistry` | Existing `deps-npm` `Registry` impl, extended into a router — no `AlternateNpmClient` type is introduced; an alternate client *is* an `NpmRegistry` with a different base | `+ tier` (public vs. workspace-declared, selecting the ungated vs. workspace transport), `+ alternates: Arc<DashMap<String, Arc<NpmRegistry>>>` (`Arc` because `NpmRegistry` is `Clone` and is cloned for `deps-deno`; capped at 256, mirroring Cargo's `MAX_ALTERNATE_REGISTRIES`) |
| `Registry::get_versions_from` / `get_latest_matching_from` | Existing defaulted `deps-core::Registry` trait methods | Overridden by `NpmRegistry`, no signature change |
| `EcosystemFormatter::can_resolve_source` / `suppress_package_url` | Existing defaulted `deps-core` trait methods | Overridden by `NpmFormatter`, no signature change |
| `EcosystemFormatter::source_is_public_registry_content` | Existing defaulted `deps-core` trait method | Deliberately **not** overridden — its default is already correct for npm. Documented side effect: alternate-sourced dependencies drop out of OSV vulnerability scanning (correct, since an advisory keyed to a public package name does not apply to a same-named private package) and out of public-registry hover links |
| `HttpCache::get_cached_workspace_with_headers` | New inherent method on `deps-core`'s `HttpCache` — the headered form of the existing `get_cached_workspace`, needed for npm's abbreviated-packument `Accept` header | Not a trait-surface change; §8's "Never widen the `deps-core` `Registry`/`EcosystemFormatter` trait surface" boundary is untouched |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| No `.npmrc` at any tier | Byte-identical to today's behavior (FR-002, US-003) |
| `@scope:registry=` present, scope unused by any dependency in the manifest | No effect — parsed but never consulted |
| `registry=` and a conflicting `@scope:registry=` for the same dependency's scope | Scope-specific entry wins (FR-004, NFR-006) |
| `registry=not-a-valid-url` | Source becomes `CustomRegistry { url: "not-a-valid-url" }`; warn logged; no public-registry fallback (FR-006, US-004) |
| `registry=${UNDEFINED_VAR}` | Treated as invalid per FR-007; no fetch attempted with the literal placeholder string |
| `registry=${DEFINED_VAR}` where the variable holds a valid https URL | Expanded and resolved normally (FR-007) — the expanded value is still subject to the full FR-006/FR-008 validation and policy gate |
| `registry=${DEFINED_VAR}` where the variable holds an invalid or policy-blocked URL | Fails closed per FR-006; the warning logs the **raw** `${DEFINED_VAR}` text, never the expanded value |
| Index URL written with a trailing slash (`https://npm.pkg.github.com/`) | Normalized to the slash-free form (NFR-002) — one router entry, and the fetch URL is `.../@scope/pkg`, not `...//@scope/pkg` |
| `.npmrc` key `@MyOrg:registry=` with a dependency `@myorg/pkg` | No match — scope keys are byte-exact and not case-folded, matching npm's own lookup |
| `registry=http://localhost:4873` (the common Verdaccio shape) in a **release** build | Rejected by URL validation → `CustomRegistry`, warn logged (FR-006). The `http`-loopback carve-out is `cfg(test)`/`test-util`-only; a release build has no `http` exception, and `HttpCache::ensure_https` would reject the URL at fetch time regardless |
| `registry=https://localhost:4873`, or an RFC1918 index host, under the default `public_only` policy | URL validation passes; blocked by FR-008's policy → `CustomRegistry`, fails closed; permitted only under `all` |
| A dependency whose source is `AlternateRegistry { index }` where `index` has no registered client (over the 256-registry cap, or a fetch racing registration) | No fetch of any kind — `PackageNotFound` naming "alternate registry (not registered)", never a fallback to `registry.npmjs.org` (FR-010) |
| A permitted public index 302-redirects to a private-range host | Blocked mid-flight by the workspace transport's per-hop re-classification (FR-008) |
| The project-tier ancestor walk reaches `$HOME` and finds the same `~/.npmrc` as the user tier | Deduped by canonicalized path (symlinked homes included) and read once |
| Version completion typed for a dependency resolved to an alternate registry | Completions come from that registry, never `registry.npmjs.org` (FR-017) |
| The same package name appears twice in one manifest resolving to different registries | No version completions offered for that name (FR-017) |
| Relative-age (freshness) suffix for an alternate-registry dependency | Absent in phase 1 — the full-packument fetch has no workspace-gated transport, so it is skipped rather than sent ungated; version data itself is unaffected (documented limitation, resolved in [[plan#Key Design Decisions\|plan]]) |
| `.npmrc` present but empty / all-comments | Equivalent to no `.npmrc` (FR-002) |
| `.npmrc` malformed (e.g. a line with no `=`) | That line is skipped; other valid lines still apply; warn logged |
| Same scope declared in both project and user `.npmrc` | Project tier wins (FR-002) |
| Alternate registry unreachable / times out | No version data shown; no panic; identical shape to public-registry-unreachable handling today |
| `.npmrc` edited after initial resolution | Stale until the affected `package.json` is next reparsed (FR-016, documented limitation) |
| Auth-shaped key present (`_authToken=...`) | Never parsed into any struct field (FR-013, NFR-001) — registry resolution proceeds unauthenticated |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Scoped private-registry dependency shows live hover/diagnostic/completion data | Pass on a real or mocked Verdaccio/Artifactory-shaped fixture |
| SC-002 | Zero regression on public-only workspaces | Every existing `deps-npm` test produces unchanged **results**. One mechanical, behavior-preserving fixture change is expected and permitted: FR-017 adds a `parse_result` parameter to `NpmEcosystem::complete_versions`, so its ~10 existing direct callers in `deps-npm/src/ecosystem.rs`'s tests gain an `empty_parse_result()` argument — which resolves to `NotInManifest` and so preserves each test's original public-registry path exactly. Cargo's equivalent change forced the identical helper (`deps-cargo/src/ecosystem.rs:374-377`). No test's *assertions* may change |
| SC-003 | No credential-shaped key is ever parsed into memory | Structural test per NFR-001 (the parser recognizes only `registry`/`@scope:registry`, no catch-all field capable of holding an auth-shaped value). The grep-based CI check originally added alongside this test was removed post-review: it produced real false positives on unrelated identifiers (e.g. `let has_auth`, `let registry_password`) with no escape hatch, and NFR-001's guarantee is already structurally enforced independent of it — see plan §12 M5 |
| SC-004 | Misconfigured/unreachable registry never silently falls back to the public registry | Test mirroring Cargo's issue-#248 regression, adapted for npm's `@scope:registry=`, asserting the resolved source is `CustomRegistry` and that no public-registry request is made — covering hover/diagnostics **and** version completion (FR-017) |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features` before considering a task complete.
- Follow the Registry Integration Gate (`.claude/rules/continuous-improvement.md`) — verify against a real or mocked private npm registry before filing the implementation PR.
- Update `CHANGELOG.md`, `ECOSYSTEM_GUIDE.md`, `.local/testing/coverage.md` (npm row), `.local/testing/playbooks/npm.md`, `.local/testing/regressions.md`.
- Reuse `DependencySource::AlternateRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `EcosystemFormatter::can_resolve_source`, and `deps_core::net_policy` as-is rather than adding parallel `deps-npm`-only mechanisms.

### Ask First
- Any decision that touches auth wiring (`_authToken`, `always-auth`) — explicitly out of scope for this spec; implementing it requires a dedicated follow-up spec given the npm-specific trust-model tension noted in Assumptions.
- Promoting `RegistryIndex` from `deps-cargo` into `deps-core` (NFR-002) — a cross-crate refactor beyond this spec's own file scope.
- Adding a `dirs`/`home`-family crate dependency to resolve `~/.npmrc` (FR-014) — Cargo's spec explicitly declined this; doing so here is a deliberate divergence that needs sign-off.
- Renaming the `cargo.workspace_registries` configuration key to `registries.workspace_registries` (FR-008) — a breaking, user-visible config change forced by `HttpCache`'s single global policy. Signed off; if the implementer finds a cheaper way to keep the policy per-ecosystem without an `HttpCache`/`Transport` refactor, re-raise before renaming.

### Never
- Parse, log, or transmit any auth-shaped `.npmrc` key in this phase (FR-013).
- Fall back to the public registry when an explicit `registry=`/`@scope:registry=` override is present but fails to resolve (FR-006) — this is the exact bug class issue #248 fixed for Cargo.
- Widen the `deps-core` `Registry`/`EcosystemFormatter` **trait** surface — every hook this spec needs already exists generically from the Cargo work. (This boundary is about traits every ecosystem must implement. Adding one inherent method to `HttpCache` — `get_cached_workspace_with_headers`, the headered form of the existing `get_cached_workspace`, needed because npm's packument fetch requires an `Accept` header — is permitted and required: without it, alternate fetches either bypass the redirect-hop-gated workspace transport or pull the full multi-MB packument on every request.)

## 9. Open Questions

- Resolved in [[plan]]: FR-006 — the fail-closed state is the existing `DependencySource::CustomRegistry { url }`, not a new variant or a `deps-npm`-local source enum; `is_version_resolvable()` is already `false` for it, so every shipped fail-closed gate applies with no `deps-core` change.
- Resolved in [[plan]]: FR-007 — a *defined* `${VAR}` is expanded from the server's process environment and then validated; only an *undefined* one is invalid. Expansion never reaches an auth-shaped key, which is not parsed at all.
- Resolved in [[plan]]: FR-008 — one shared `registries.workspace_registries` setting (the renamed `cargo.workspace_registries`) governs every ecosystem, because `HttpCache` holds exactly one global policy. A separate `npm.*` key was rejected as last-writer-wins and a silent widening of Cargo's SSRF gate. Per-ecosystem policy needs an `HttpCache`/`Transport` refactor and is a tracked follow-up.
- Resolved in [[plan]]: FR-011 — alternate-registry package-*name* search/completion is an unconditional no-op, mirroring Cargo's simpler choice; no allow-list or runtime probe. Version completion is *not* covered by this and is handled by FR-017.
- Resolved in [[plan]]: FR-012 — `.npmrc` parsing is memoized per file path (raw entries + mtime), mirroring `deps-cargo`'s `ConfigFileCache`; there is no workspace-root key, because npm has no workspace-root concept for config discovery and neither does Cargo's config cache.
- Resolved in [[plan]]: FR-014 — adds the `dirs` crate (v6) for `~/.npmrc` resolution, a deliberate divergence from Cargo's raw-env-var-only precedent, signed off given npm's heavier reliance on the user-tier config file.
- Resolved in [[plan]]: FR-017 — version completion routes on the dependency's already-resolved source via a private `CompletionSource`/`resolve_completion_source` pair inside `deps-npm`, mirroring Cargo's FR-012. `generate_completions` already carries `parse_result`, so no `deps-core` signature changes.
- Resolved in [[plan]]: NFR-002 — `RegistryIndex` is not promoted to `deps-core`; `deps-npm` gets its own minimal `NpmRegistryIndex` newtype with no trust-tier concept, since Cargo's type is coupled to auth-provenance semantics npm's auth-free phase 1 doesn't need.
- **Explicitly deferred, not a blocking question**: the full auth-wiring problem (`_authToken`, `always-auth`, env-var interpolation of credentials) is scoped out of phase 1 entirely (see Out of Scope) rather than left as an in-spec open question, because the design tension it raises (npm's convention of committing an env-interpolated token to a project `.npmrc`, versus Cargo's rule that a workspace file must never be a credential source) needs its own dedicated spec once phase 1's registry-routing mechanism has shipped and been validated.

## 10. See Also

- [[constitution]] — project principles (not yet created for this project; cross-check against `.claude/rules/*.md` instead)
- [[MOC-specs]] — all specifications
- [[023-cargo-custom-registries/spec|023-cargo-custom-registries]] — the reference implementation pattern this spec follows: `DependencySource::AlternateRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `EcosystemFormatter::can_resolve_source`, `deps_core::net_policy` host-classifier gating — all reused here without modification
- `.local/testing/playbooks/competitive-parity.md` — "Private/alternative registry support" row naming npm, Maven, NuGet, pip, Go, Composer, and Bundler as unfiled follow-ons to the Cargo pattern
- Dependi private-registry demand evidence (different repository, links intentionally not auto-linked): `` github.com/filllabs/dependi/issues/211 ``, `` github.com/filllabs/dependi/issues/214 ``, `` github.com/filllabs/dependi/issues/285 ``, `` github.com/filllabs/dependi/issues/292 ``, `` github.com/filllabs/dependi/issues/293 ``, `` github.com/filllabs/dependi/issues/18 ``
- `crates/deps-core/src/parser.rs` — `DependencySource`, `AlternateRegistry`, `is_version_resolvable`
- `crates/deps-core/src/registry.rs` — `Registry` trait, `get_versions_from`/`get_latest_matching_from`
- `crates/deps-core/src/net_policy.rs` — `HostClass`, `classify_host`, `RegistryAccessPolicy`, `WorkspaceRegistryAccess`
- `crates/deps-cargo/src/config.rs` — `RegistryIndex` (candidate for promotion, NFR-002), `.cargo/config.toml` resolution pattern to mirror for `.npmrc`
- `crates/deps-npm/src/registry.rs` — `REGISTRY_BASE`, the hardcoded constant this spec replaces with per-dependency resolution
- `crates/deps-npm/src/parser.rs` — existing scoped-package-name parsing (`test_scoped_package`) this spec builds registry resolution on top of
- Issue #248 — the Cargo silent-fallback-to-public-registry bug this spec's FR-006/US-004 explicitly avoid repeating for npm

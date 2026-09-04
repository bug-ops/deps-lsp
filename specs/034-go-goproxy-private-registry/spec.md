---
aliases:
  - Go GOPROXY / GOPRIVATE Support
  - Go Private Module Proxy Resolution
tags:
  - sdd
  - spec
  - research
  - enhancement
  - go
  - security
created: 2026-09-03
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
  - "[[032-npm-npmrc-registry-support/spec|npm .npmrc Custom/Private Registry Support]]"
  - "[[033-pypi-private-index-support/spec|PyPI Private/Custom Index Resolution]]"
---

# Feature: Go `GOPROXY`/`GOPRIVATE` Module Proxy Resolution

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Issue**: #519
> **Branch**: (assign at implementation time, e.g. `feat/<issue>-go-goproxy-private-registry`)
> **Priority**: P3
> **Type**: research/enhancement (competitive parity gap)

## 1. Overview

### Problem Statement

`deps-go` has zero support for `GOPROXY`/`GOPRIVATE` module-proxy resolution
— confirmed live this session by reading the crate directly:

- `crates/deps-go/src/registry.rs:35` hardcodes
  `const PROXY_BASE: &str = "https://proxy.golang.org";` with no override
  path of any kind — every module version lookup (`@v/list`, `@v/{version}.info`,
  `@v/{version}.mod`, `@latest`) is spliced onto this constant unconditionally,
  regardless of any project or environment configuration.
- `grep -rli` across `crates/deps-go/src/` for `GOPROXY`, `GONOSUMCHECK`,
  `GOPRIVATE`, `GONOSUMDB`, or `GOFLAGS` returns zero hits — none of these
  environment variables, nor any file-based equivalent, are recognized
  anywhere in the crate.
- No `$GOENV` config-file reading (Go's own `go env -w`-managed persistent
  config file, analogous to npm's `.npmrc` or pip's `pip.conf`) exists in
  the crate.

This is the same silent-wrong-data bug class already fixed three times in
this project: Cargo (`.cargo/config.toml` `[registries]`/`[source]`,
issues/PRs #431/#440/#441/#447), npm (`.npmrc` scoped/top-level `registry=`,
issue #502, PR #510), and PyPI (`--index-url`/`--extra-index-url`/Poetry
`[[tool.poetry.source]]`/uv `[tool.uv.index]`, issue #513, PR #516). Any
workspace routing Go module resolution through a private proxy (Athens,
JFrog Artifactory Go registry, Google's Go Module Proxy for private repos,
a corporate GOPROXY mirror) or marking module paths as `GOPRIVATE` gets
hover/diagnostic/completion data resolved against — or, worse, silently
leaked to — the public `proxy.golang.org` with no indication anything is
off. This project's own `.claude/rules/continuous-improvement.md` names
`GOPROXY` explicitly in its "Dependency Monitoring" key-env-var list, and
the competitive-parity playbook's originally-identified private-registry
gap list has always named GOPROXY alongside `.npmrc`/Cargo-alt-registries/
NuGet-feeds/pip-extra-index-url — it was simply never prioritized over
Cargo/npm/PyPI until now, since those three are shipped.

`deps-cargo`, `deps-npm`, and `deps-pypi` already ship a proven reference
pattern for exactly this class of problem, and the shared infrastructure in
`deps-core` is generic enough that `deps-go` needs no `deps-core` change to
reuse it:

- `DependencySource::AlternateRegistry { index, mirrors_crates_io }`
  (`crates/deps-core/src/parser.rs`) — a source-agnostic "resolved to a
  concrete, fetchable index/proxy URL" variant. `deps-go` would construct
  it directly (`mirrors_crates_io: false`, matching npm's and PyPI's choice
  — no analogous mirror-verification concept exists for a Go proxy).
- `DependencySource::CustomRegistry { url }` — the existing "present, but
  not resolved to a concrete, fetchable proxy" fail-closed state.
  `is_version_resolvable()` is already `false` for it, so every existing
  fail-closed gate (hover, diagnostics, code actions) applies with zero new
  code.
- `Registry::get_versions_from` / `get_latest_matching_from` — defaulted
  trait methods any `Registry` impl can override; `GoRegistry` would
  override these exactly as `CargoRegistry`/`NpmRegistry`/`PypiRegistry` do.
- `EcosystemFormatter`'s `SourcePolicy` supertrait (one of the seven
  concern-scoped supertraits `EcosystemFormatter` was split into by #515;
  see `crates/deps-core/src/lsp_helpers/mod.rs`) and its
  `can_resolve_source` hook (defaulted to
  `DependencySource::is_version_resolvable()`) — the single override point
  gating hover/diagnostics/code-actions; `GoFormatter` would implement
  `SourcePolicy` and override this hook exactly as the other three
  ecosystems' formatters do.
- `deps_core::net_policy` (`HostClass`, `classify_host`,
  `RegistryAccessPolicy`, `WorkspaceRegistryAccess`) — the SSRF-hardening
  host classifier already gating Cargo's/npm's/PyPI's workspace-declared
  registries behind the shared `registries.workspace_registries` setting
  (`off` / `public_only` / `all`, default `public_only`). `deps-go` reuses
  this same setting.

What `deps-go` needs on top of that shared foundation is Go-specific:
parsing a `$GOENV`-style `KEY=VALUE` config file for `GOPROXY`/`GOPRIVATE`,
`GOPROXY`'s ordered fallback-chain-with-`direct`/`off`-sentinel semantics,
and `GOPRIVATE`'s glob-pattern-on-module-path routing — none of which has a
clean analogue in any of the three shipped ecosystems (see the Go-Specific
Nuances subsection below). The crate's existing module-path escaping
(`escape_module_path`, `crates/deps-go/src/version.rs`, used throughout
`registry.rs` when building `PROXY_BASE`-relative URLs) must apply
identically to any resolved private proxy host — this is a reuse
requirement, not new logic.

**Demand evidence** (verified live this session):

- `filllabs/dependi` (deps-lsp's closest tracked competitor, per this
  project's competitive-parity playbook) has issue
  `` filllabs/dependi#18 `` open: "Support for automatic reading and
  recognition of go env environment variables is required" — a direct ask
  for `GOPROXY`/`GOPRIVATE`/`GONOSUMCHECK` support, i.e. exactly this gap.
- Of the six private-registry issues previously tracked against Dependi
  (`` #211 ``, `` #214 ``, `` #285 ``, `` #292 ``, `` #293 ``, `` #18 ``,
  checked via `gh issue view -R filllabs/dependi` this session): `` #211 ``
  and `` #214 `` are npm/Cargo (already shipped in deps-lsp via #440/#447
  and #510), `` #285 ``/`` #292 ``/`` #293 `` are PyPI (already shipped via
  #516), leaving `` #18 `` (Go) as the only remaining ecosystem with a
  direct, still-open competitor demand signal among the six originally
  tracked.
- `gh issue list --search "GOPROXY"` / `--search "go proxy private"` /
  `--search "deps-go registry"` against this repository (`bug-ops/deps-lsp`)
  returned zero hits this session — not a duplicate of an existing open or
  closed issue.

> [!warning] Assumptions
> - Target proxies speak the standard Go module proxy protocol
>   (`GET $proxy/{module}/@v/list`, `@v/{version}.info`, `@v/{version}.mod`,
>   `@latest`) that `deps-go` already implements for the public proxy —
>   Athens, JFrog Artifactory's Go registry, Sonatype Nexus Go proxy repos,
>   and GitLab's Go proxy all implement this protocol. A proxy speaking a
>   non-standard shape is out of scope, matching how the Cargo/npm/PyPI
>   specs scoped out non-standard-protocol registries.
> - Since deps-lsp reads project/config files rather than live shell
>   environment variables by convention (matching npm's `.npmrc`-file-only
>   phase-1 scope and PyPI's manifest-only phase-1 scope), this spec targets
>   the `$GOENV` config file (default path per `go env -w`'s own
>   documentation: `os.UserConfigDir()/go/env`, e.g.
>   `~/.config/go/env` on Linux/macOS, `%AppData%\go\env` on Windows) as the
>   phase-1 configuration surface for `GOPROXY`/`GOPRIVATE`, rather than
>   reading the process's live `GOPROXY`/`GOPRIVATE` environment variables.
>   Live env-var reading is a materially different scope/precedence
>   question — see Open Questions.
> - `GOPROXY`'s comma-or-pipe-separated ordered list with `direct`/`off`
>   sentinels (`go help goproxy`) and `GOPRIVATE`'s comma-separated
>   glob-pattern module-path-prefix list (`go help environment`) are the
>   authoritative semantics this spec's Functional Requirements are built
>   against.
> - **Divergent from Cargo/npm/PyPI's trust model, resolved for phase 1**: a
>   Go module proxy URL may embed HTTP basic-auth userinfo
>   (`https://user:pass@proxy.example/`) per Go's own documented
>   convention, or rely on `.netrc` credential resolution outside the URL
>   entirely (`go help goproxy` documents both). Neither is addressed in
>   phase 1, matching the Cargo/npm/PyPI precedent exactly — see Out of
>   Scope and Open Questions for the resolved deferral.
> - **FR-006's `direct` sentinel, resolved for phase 1 by direct code
>   inspection this session**: `crates/deps-go/src/registry.rs` exposes
>   exactly four resolution methods (`get_versions`, `get_version_info`,
>   `get_latest`, `get_go_mod`), all built on `version_url`/`package_url`
>   relative to `PROXY_BASE` — the Go module-proxy-protocol client only.
>   There is no direct-VCS resolution path (no git-tags client, no
>   go-import-meta-tag discovery, no arbitrary-VCS clone/fetch mechanism)
>   anywhere in the crate. The closest existing analogue in the workspace,
>   `GithubActionsRegistry`'s tags client (`crates/deps-github-actions/src/registry.rs`),
>   is GitHub-specific (owner/repo REST API) and not a fit: Go's `direct`
>   mode must support arbitrary VCS hosts/protocols via the `go-import`
>   HTML meta-tag discovery protocol (`go help importpath`), a materially
>   larger, unrelated-protocol build. Phase 1 therefore implements `direct`
>   as a fail-closed terminal hop (no version data), per FR-006's own
>   stated fallback — this is not a scope gap requiring further
>   clarification, it is the confirmed answer.

### Goal

A Go module dependency whose applicable proxy is overridden via a
`$GOENV` `GOPROXY=` entry, or whose module path matches a `$GOENV`
`GOPRIVATE=` glob pattern (routing it to `direct`), gets the same
hover/diagnostic/completion value a `proxy.golang.org`-resolved dependency
gets today — with zero regression for projects declaring no override, and
with no credential ever read, stored, or transmitted in this phase (auth
wiring deferred, see Out of Scope).

### Out of Scope

> [!danger] Explicit Exclusions
> - **All auth/credential handling** — HTTP basic-auth embedded in a proxy
>   URL (`https://user:pass@host/`), Go's `.netrc` resolution, and
>   `GOPROXY`-embedded credential forms. Phase 1 resolves *which* proxy (or
>   `direct`) a module belongs to and fetches it unauthenticated; any URL
>   with embedded userinfo fails closed, matching the Cargo/npm/PyPI
>   precedent exactly — it never reads, stores, or transmits a credential.
>   `.netrc` receives no detection or acknowledgment in phase 1. A dedicated
>   follow-up spec is the right place to revisit Go's broader credential
>   conventions, **resolved to include** `GOPROXY`'s documented support for
>   a bare local-filesystem-path entry in that same follow-up's scope — it
>   has no auth concept, but shares the follow-up's "hop needs its own
>   validation surface beyond https-URL-shaped entries" theme (path
>   traversal, not credential handling) and splitting it into a third,
>   separate spec adds process overhead with no benefit.
> - **Live shell/process environment-variable reading**
>   (`GOPROXY`/`GOPRIVATE`/`GONOSUMCHECK`/`GONOSUMDB`/`GOFLAGS` read from the
>   LSP server's own process environment, or from a `.env`-style file).
>   Phase 1 targets the file-based `$GOENV` config only (see Assumptions).
>   **Resolved**: no concrete workspace/editor-launch demand signal was
>   found for this (no issue, no Dependi parity gap naming it specifically),
>   so file-based `$GOENV`-only is sufficient for phase 1, matching the
>   npm/PyPI precedent (neither reads live env vars either) — left
>   unscheduled rather than spun into a tracked follow-up, consistent with
>   how 032/033 left their own equivalent gaps.
> - **Checksum-database verification** (`GONOSUMCHECK=1`, `GOSUMDB=off`,
>   and Go's checksum-database (`sum.golang.org`) protocol in general) — no
>   checksum verification exists in `deps-go` today, or in any other
>   ecosystem crate in this project; a version-hint LSP has no natural
>   place to enforce this, and it is a distinct problem (integrity
>   verification) from registry/proxy routing.
> - **`go.sum` parsing or cross-referencing** — this spec is scoped to
>   proxy *routing* for version resolution (`go.mod` dependencies), not to
>   validating or reconciling `go.sum` entries against a resolved proxy.
> - **`GOFLAGS=-insecure`** and any other `GOFLAGS`-mediated behavior —
>   `GOFLAGS` is a general flag-injection mechanism for the `go` CLI, not a
>   registry-routing concern; out of scope entirely.
> - **Package-name search/completion** for a proxy that does not implement
>   a Go-proxy-protocol-compatible listing — same choice
>   [[032-npm-npmrc-registry-support/spec|032]]'s FR-011 and
>   [[033-pypi-private-index-support/spec|033]]'s FR-014 made: unconditional
>   no-op for alternate-proxy-resolved dependencies rather than a per-proxy
>   capability probe. Go module proxies have no package-name search
>   endpoint in the protocol at all (unlike npm's `-/v1/search` or PyPI's
>   Simple index listing), so this exclusion is unconditional rather than
>   conditional on protocol support.
> - **A dedicated `$GOENV` file watcher** — same choice Cargo's FR-013,
>   npm's FR-016, and PyPI's FR-012 made: document staleness (edits take
>   effect on next reparse of the affected `go.mod`) rather than build a new
>   watcher subsystem.
> - **`vendor/` directory resolution** (`GOFLAGS=-mod=vendor` / `go.mod`'s
>   own vendor-consistency checking) — a distinct dependency-provenance
>   concern, not registry/proxy routing; out of scope.

## 2. User Stories

### US-001: `GOPROXY` full-chain resolution via `$GOENV`

AS A developer whose company routes all Go module traffic through a
corporate proxy (Athens/Artifactory/Nexus)
I WANT dependencies in `go.mod` to resolve against that proxy
SO THAT hover/diagnostics reflect what my proxy actually serves (which may
lag, mirror, or diverge from the public `proxy.golang.org`)

**Acceptance criteria:**
```
GIVEN a $GOENV file containing
      GOPROXY=https://goproxy.mycorp.example,direct
WHEN I hover over any dependency declared in go.mod
THEN the hover reflects goproxy.mycorp.example's data first, falling
     through to a direct VCS fetch only if the proxy reports the module
     is absent, and no request is sent to proxy.golang.org
```

### US-002: `GOPRIVATE` glob-pattern routing to `direct`

AS A developer with private company modules under a shared module-path
prefix (`git.mycorp.example/*`)
I WANT those modules to bypass the public proxy entirely
SO THAT a private module's path is never disclosed to `proxy.golang.org`
or any public proxy, mirroring the confidentiality guarantee Go's own
tooling provides

**Acceptance criteria:**
```
GIVEN a $GOENV file containing
      GOPRIVATE=git.mycorp.example/*
  AND a go.mod dependency on git.mycorp.example/internal/auth
WHEN I hover over that dependency
THEN resolution routes to the direct hop, never to proxy.golang.org
     or any GOPROXY-configured public-tier proxy, for that module path
     (phase 1: the direct hop fails closed per FR-006/US-003 — no version
     data shown — but confidentiality is preserved regardless, since no
     request naming this module path is ever sent to a public proxy)
```

### US-003: `GOPROXY` ordered fallback chain reaches the `direct` sentinel

AS A developer relying on Go's default `GOPROXY` behavior
(`https://proxy.golang.org,direct`)
I WANT the LSP to correctly detect when a module falls through to the
`direct` hop, rather than silently misreporting it as available on a
proxy hop that actually reported it absent
SO THAT I can trust the hover/diagnostic result's absence of data means
"phase 1 doesn't resolve `direct` yet," not "this module doesn't exist"

**Acceptance criteria:**
```
GIVEN a $GOENV file containing
      GOPROXY=https://goproxy.mycorp.example,direct
  AND a module absent from goproxy.mycorp.example
WHEN I hover over that dependency
THEN the LSP falls through past the proxy hop to the direct sentinel
     (FR-005), and shows no version data there (FR-006 — direct-VCS
     resolution is a fail-closed no-op in phase 1, per Open Questions),
     rather than treating the proxy's not-found response as final
```

> [!note] Phase 1 scope
> Genuine direct-VCS-resolved data (US-003's original framing) requires a
> follow-up spec — see Open Questions. Phase 1 only guarantees the chain
> mechanics (proxy hop exhausted → fall through → terminal `direct`
> no-op) are correct, not that `direct` itself produces version data.

### US-004: `GOPROXY=off` fails closed

AS A developer who has explicitly set `GOPROXY=off` (disallowing all
module downloads, per Go's own semantics)
I WANT the LSP to show no version data rather than silently querying the
public proxy anyway
SO THAT the LSP's behavior matches what `go build`/`go get` would actually
do in this environment

**Acceptance criteria:**
```
GIVEN a $GOENV file containing GOPROXY=off
WHEN I hover over any go.mod dependency
THEN no version data is shown, and no request is sent to
     proxy.golang.org or any other host
```

### US-005: No regression for projects declaring no override

AS A developer with no `$GOENV` file, or one that declares no
`GOPROXY`/`GOPRIVATE` override
I WANT the LSP to keep behaving exactly as it does today
SO THAT this feature introduces zero risk for the overwhelming majority of
Go projects

**Acceptance criteria:**
```
GIVEN no $GOENV file exists, or it exists but declares no GOPROXY/GOPRIVATE
WHEN I hover over any go.mod dependency
THEN the hover is byte-identical to pre-feature behavior (proxy.golang.org)
```

### US-006: Unresolved/misconfigured proxy fails closed

AS A developer whose `GOPROXY` entry points at an unreachable, invalid, or
policy-blocked URL
I WANT the LSP to show no data for dependencies routed to it rather than
silently checking the public proxy
SO THAT I never mistake a stale/wrong public-proxy result for my private
proxy's actual state

**Acceptance criteria:**
```
GIVEN GOPROXY=not-a-valid-url in $GOENV
WHEN I hover over any go.mod dependency
THEN no version data is shown, and no request is sent to
     proxy.golang.org for that dependency (mirrors the regression class
     issue #248 fixed for Cargo and the equivalent classes 032/033 closed
     for npm/PyPI)
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL locate and parse the `$GOENV` config file (env var `GOENV` if set, else the platform default `os.UserConfigDir()/go/env`) as `KEY=VALUE` lines (one per line, `#`-prefixed comment lines and blank lines ignored, matching `go env -w`'s own written format) | must |
| FR-002 | THE SYSTEM SHALL parse a `GOPROXY` entry as a comma-or-pipe-separated ordered list of chain hops, recognizing the two sentinel values `direct` (resolve straight from the VCS host, no proxy) and `off` (disallow all downloads), per `go help goproxy` semantics | must |
| FR-003 | WHEN `GOPROXY` is absent from `$GOENV` THE SYSTEM SHALL use Go's documented default chain (`https://proxy.golang.org,direct`) — this is the existing `PROXY_BASE` behavior, now expressed as the default of an overridable chain rather than a hardcoded constant | must |
| FR-004 | WHEN `GOPROXY=off` (as the sole entry, or reached as the terminal hop of the chain) THE SYSTEM SHALL show no version data for every affected module and SHALL NOT send any network request for that module — mirrors `go build`'s own behavior under `GOPROXY=off` | must |
| FR-005 | WHEN a chain hop is a proxy URL (not `direct`/`off`) and the module is reported absent by that hop (an explicit "not found" response, matching the existing not-found handling `deps-go` already applies to `proxy.golang.org`) THE SYSTEM SHALL fall through to the next hop in declaration order. A transport failure (connection error, timeout, 5xx) on a hop SHALL be treated as terminal for that hop's chain — not silently skipped — mirroring PyPI's FR-005(c) precedent (033) and for the same reason: silently falling through on transport failure risks resolving a module through a fallback the user did not intend for the reachability state they are actually in | must |
| FR-006 | WHEN a chain hop is the `direct` sentinel THE SYSTEM SHALL treat it as an unresolvable terminal hop and show no version data — confirmed by direct code inspection (see Assumptions) that `deps-go` has no direct-VCS resolution mechanism today; phase 1 is necessarily a fail-closed no-op for `direct`, deferred to a follow-up that would implement actual direct-VCS resolution | must |
| FR-007 | THE SYSTEM SHALL parse a `GOPRIVATE` entry as a comma-separated list of glob patterns (Go's own `path.Match`-style glob syntax, per `go help goprivate`/`go help environment`), matched against a module's full path | must |
| FR-008 | WHEN a module's path matches a `GOPRIVATE` glob pattern THE SYSTEM SHALL route that module directly to the `direct` resolution behavior (FR-006), bypassing every proxy hop in the `GOPROXY` chain entirely — regardless of what `GOPROXY` is configured to — matching Go's own documented behavior that `GOPRIVATE`-matched modules never reach a configured proxy or its checksum database | must |
| FR-009 | WHEN a `GOPROXY` chain hop URL is present but fails validation (non-https, contains userinfo, or is not well-formed — neither `direct` nor `off`) or is blocked by FR-011's policy THE SYSTEM SHALL treat that hop as an invalid entry: represent the affected module's source as `DependencySource::CustomRegistry { url: <the raw value as written> }` if it is the only remaining viable hop, or drop the invalid hop and continue to the next chain entry if other valid hops remain — mirroring PyPI's FR-006 (033) per-entry-fail-closed rule, logging a `tracing::warn!` naming the raw value, and SHALL NOT fall back to `proxy.golang.org` for a module whose resolution the user explicitly overrode | must |
| FR-010 | THE SYSTEM SHALL apply `escape_module_path`/`escape_version` (`crates/deps-go/src/version.rs`) identically when constructing request URLs against any resolved private proxy host, exactly as already done for `PROXY_BASE` — no separate escaping logic for alternate proxies | must |
| FR-011 | THE SYSTEM SHALL classify every explicitly-declared `GOPROXY` chain hop's host through `deps_core::net_policy::classify_host` and gate the fetch behind the existing shared `registries.workspace_registries` setting (`off` / `public_only` / `all`, default `public_only`) — the same setting Cargo/npm/PyPI already gate on, reused as-is with no new `go.*` key. The default public chain (`https://proxy.golang.org,direct`) used when `$GOENV` declares no `GOPROXY` override is never subject to this gate — it is the same ungated public-tier client `deps-go` already uses today | must |
| FR-012 | THE SYSTEM SHALL add `GoFormatter`'s implementation of the `SourcePolicy` supertrait's `can_resolve_source` hook (overriding the existing defaulted `EcosystemFormatter::can_resolve_source`) so hover/diagnostics/code-actions correctly gate on a resolved `AlternateRegistry` source — no `deps-core` trait change required | must |
| FR-013 | THE SYSTEM SHALL add `Registry::get_versions_from` / `get_latest_matching_from` overrides on `GoRegistry`, routing fetches for `AlternateRegistry`-sourced dependencies to the resolved chain instead of unconditional `PROXY_BASE` — reuses the existing defaulted `deps-core::Registry` trait methods. WHEN a resolved `AlternateRegistry`'s chain has no registered client for a hop THE SYSTEM SHALL return `PackageNotFound`/proceed to the next hop per FR-005, and SHALL NOT fall back to `proxy.golang.org` outside the configured chain's own `direct`/default-inclusion rules | must |
| FR-014 | THE SYSTEM SHALL NOT read, log, or transmit any embedded URL userinfo (`user:pass@`) or any other credential-shaped value from a `GOPROXY` entry — parsing SHALL reject (per FR-009) rather than strip-and-proceed, so no code path ever holds a credential value in memory. Any warning naming a rejected entry SHALL use a redacted form (userinfo replaced with a fixed marker), matching PyPI's FR-011 (033) precedent | must — security-blocking |
| FR-015 | THE SYSTEM SHALL document `$GOENV` staleness as a known limitation (edits take effect on next reparse of the affected `go.mod`) rather than add a dedicated file watcher, mirroring Cargo's FR-013, npm's FR-016, and PyPI's FR-012 resolution | must — the choice itself, not a specific mechanism, is mandatory |
| FR-016 | Package-name search/completion for a dependency resolved to a non-default `GOPROXY` chain or `GOPRIVATE`-routed `direct` SHALL no-op rather than error or query `proxy.golang.org`, mirroring 032's FR-011 and 033's FR-014 | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No credential-shaped value (URL userinfo, or any future `.netrc`-adjacent field) is ever parsed, held in memory, logged, or transmitted in phase 1 — verified by a structural test asserting the parsed config type has no field capable of holding such a value, matching the pattern Cargo's NFR-001, npm's NFR-001, and PyPI's NFR-001 established |
| NFR-002 | Security | Every resolved `GOPROXY` chain hop URL is validated (https-only, no userinfo, with the same test-only loopback carve-out precedent as Cargo/npm/PyPI) and normalized before any network request |
| NFR-003 | Security | Two residual risks, both must be stated for security-reviewer sign-off before implementation merges. **(1) Inbound reachability**: an unauthenticated HTTPS GET to a workspace-declared proxy still occurs, which is reachability into the user's internal network usable for existence probing by a hostile repository — mitigated identically to Cargo/npm/PyPI by `registries.workspace_registries` defaulting to `public_only`. **(2) GOPRIVATE confidentiality guarantee**: FR-008's bypass-the-chain-entirely rule for `GOPRIVATE`-matched modules exists specifically so a private module path is never sent to `proxy.golang.org` or any configured public-tier proxy — this mirrors the exact protection Go's own tooling provides and must not be weakened by, e.g., accidentally including a `GOPRIVATE`-matched module in a chain-wide batch request to a public proxy hop |
| NFR-004 | Performance | No additional filesystem/network activity for a project declaring no `$GOENV` override, or a `$GOENV` file that declares neither `GOPROXY` nor `GOPRIVATE` — zero regression path, verified by existing test suite |
| NFR-005 | Reliability | Zero behavior change for any project declaring no `GOPROXY`/`GOPRIVATE` override — verified by the existing `deps-go` test suite producing unchanged results |
| NFR-006 | Maintainability | FR-005's fallback-chain ordering and FR-008's `GOPRIVATE` bypass are each verified by dedicated tests: (a) a module absent from a proxy hop falls through to the next hop; (b) a transport failure on a hop is terminal, not skipped; (c) a `GOPRIVATE`-matched module never reaches any proxy hop regardless of `GOPROXY` configuration |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencySource::AlternateRegistry` | Existing `deps-core` variant, reused as-is — the FR-002/FR-007 resolved state | `index: String` — for Go, an opaque routing key identifying the resolved chain/hop (mirrors PyPI's `ResolvedChain::key` precedent for multi-hop sources, per 033's Data Model note on this field's widened contract), `mirrors_crates_io: bool` (always `false`) |
| `DependencySource::CustomRegistry` | Existing `deps-core` variant, reused as Go's FR-009 fail-closed state — no new variant introduced | `url: String` — the raw value as written; `is_version_resolvable()` already `false` |
| `GoEnvConfig` | New `deps-go` type — parsed `$GOENV` file contents | `goproxy: Option<Result<GoProxyChain, InvalidEntry>>`, `goprivate: Option<Vec<GlobPattern>>` |
| `GoProxyChain` | New `deps-go` type — an ordered, validated `GOPROXY` chain | `hops: Vec<GoProxyHop>` (declaration order preserved, FR-002/FR-005) |
| `GoProxyHop` | New `deps-go` type — one chain entry | Either a validated `GoProxyUrl`, or the `Direct`/`Off` sentinel variant, or an `InvalidEntry` (FR-009) |
| `GoProxyUrl` | Validated, normalized proxy URL newtype, new and `deps-go`-local (mirrors `NpmRegistryIndex`/`PypiIndexUrl` rather than promoting a shared type, per the same "wait for a third+ near-identical implementation" principle 033 applied — this would be the fourth) | https-only, no userinfo |
| `InvalidEntry` | New `deps-go` type — a present-but-unusable chain hop, carrying what FR-009 needs to build `CustomRegistry` and to warn | `raw: String` (as written), `reason` (validation failure kind) |
| `GlobPattern` | New `deps-go` type — one `GOPRIVATE` module-path-prefix glob | The pattern as parsed, matched per Go's `path.Match`-style glob syntax against a module's full path (FR-007/FR-008) |
| `GoRegistry` | Existing `deps-go` `Registry` impl, extended into a chain-aware router mirroring `PypiRegistry`'s `fallback_chain` structure (033) | `+ resolved_chains: <map keyed by opaque routing key>` (root-owned only), `+ private_patterns: Vec<GlobPattern>` |
| `Registry::get_versions_from` / `get_latest_matching_from` | Existing defaulted `deps-core::Registry` trait methods | Overridden by `GoRegistry`, no signature change |
| `EcosystemFormatter`'s `SourcePolicy` supertrait / `can_resolve_source` | Existing defaulted `deps-core` trait method (part of the seven-supertrait split from #515) | Implemented/overridden by `GoFormatter`, no signature change |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| No `$GOENV` file, or it exists but declares no `GOPROXY`/`GOPRIVATE` | Byte-identical to today's behavior (US-005) |
| `GOPROXY=https://goproxy.mycorp.example,direct` | Every dependency routes to the private proxy first, falling through to `direct` only on explicit not-found (FR-002, FR-005, US-001, US-003) |
| `GOPROXY=off` | No version data shown for any dependency; no network request sent (FR-004, US-004) |
| `GOPROXY=not-a-valid-url` (sole entry) | Source becomes `CustomRegistry { url: "not-a-valid-url" }`; warn logged; no `proxy.golang.org` fallback (FR-009, US-006) |
| `GOPROXY=not-a-valid-url,https://goproxy.mycorp.example` | Invalid first hop dropped (warn logged); resolution proceeds via the remaining valid hop (FR-009) |
| `GOPRIVATE=git.mycorp.example/*`, module path `git.mycorp.example/internal/auth` | Routed directly to `direct`, bypassing every `GOPROXY` hop regardless of configuration (FR-008, US-002) |
| `GOPRIVATE` glob does not match a module's path | `GOPROXY` chain applies normally — no effect from `GOPRIVATE` for that module |
| Module absent from a configured proxy hop, present via `direct` VCS resolution | Resolved via `direct` after the proxy's explicit not-found response (FR-005, US-003) |
| A configured proxy hop is unreachable (connection error/timeout) with further hops declared | Resolution halts at that hop rather than silently skipping to the next — a distinguishable outcome, not a generic failure (FR-005, mirrors PyPI's 033 FR-005(c)/NFR-003(3) trade-off) |
| Proxy URL contains embedded userinfo (`https://user:pass@host/`) | Rejected per FR-009/FR-014 → fails closed per the entry-specific rule (Cargo/npm/PyPI precedent) |
| `workspace_registries = off`, `$GOENV` declares a private `GOPROXY` hop | That hop is blocked by FR-011's policy → dropped/fails closed per FR-009, same as an invalid entry |
| `$GOENV` edited after initial resolution | Stale until the affected `go.mod` is next reparsed (FR-015, documented limitation) |
| `GOENV` environment variable set to a custom path | THE SYSTEM SHALL honor it per FR-001, consistent with `go env`'s own resolution order |
| `direct` sentinel reached | Treated as an unresolvable terminal hop — no version data shown (FR-006, confirmed: `deps-go` has no direct-VCS resolution mechanism) |
| Live `GOPROXY`/`GOPRIVATE` process environment variables set, no `$GOENV` override | No effect in phase 1 (Out of Scope) — dependencies resolve exactly as they do today, a known false-negative for that class of project until the deferred follow-up ships |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Private-proxy dependency (via `GOPROXY`) shows live hover/diagnostic/completion data | Pass on a real or mocked Athens/Artifactory-shaped fixture |
| SC-002 | `GOPRIVATE`-matched module never sends a request to `proxy.golang.org` or any configured public-tier `GOPROXY` hop | Test asserting zero requests to the public/default chain for a `GOPRIVATE`-matched module path |
| SC-003 | Zero regression on projects declaring no `$GOENV` override | Every existing `deps-go` test produces unchanged results |
| SC-004 | Misconfigured/unreachable proxy hop never silently falls back to `proxy.golang.org` ahead of a valid remaining/declared hop | Test mirroring the #248/032/033 regression pattern, adapted for Go's ordered-chain model |
| SC-005 | No credential-shaped value is ever parsed into memory | Structural test per NFR-001/FR-014 |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features` before considering a task complete.
- Follow the Registry Integration Gate (`.claude/rules/continuous-improvement.md`) — verify against a real or mocked private Go module proxy before filing the implementation PR.
- Update `CHANGELOG.md`, `ECOSYSTEM_GUIDE.md`, `.local/testing/coverage.md` (Go row), `.local/testing/playbooks/go.md` (create if absent), `.local/testing/regressions.md`.
- Reuse `DependencySource::AlternateRegistry`/`CustomRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `SourcePolicy`'s `can_resolve_source`, `deps_core::net_policy`, and `escape_module_path`/`escape_version` as-is rather than adding parallel `deps-go`-only mechanisms.

### Ask First
- Any decision that touches auth/credential handling (URL userinfo, `.netrc`) — explicitly out of scope for this spec; a dedicated follow-up spec owns Go's broader credential conventions.
- Implementing live `GOPROXY`/`GOPRIVATE` process-environment-variable reading — explicitly out of scope for phase 1, deferred pending the Open Questions resolution.
- Implementing FR-006's `direct` sentinel as an actual VCS-resolution mechanism (rather than a fail-closed no-op) if `deps-go` has no existing direct-VCS resolution path — this is a materially larger scope than proxy routing and needs explicit sign-off.
- Consolidating `GoProxyUrl` with Cargo's `RegistryIndex`/npm's `NpmRegistryIndex`/PyPI's `PypiIndexUrl` into a shared `deps-core` type — a cross-crate refactor beyond this spec's own file scope.

### Never
- Parse, log, or transmit any credential-shaped value (URL userinfo or otherwise) in this phase (FR-014).
- Fall back to `proxy.golang.org` when an explicit `GOPROXY` override is present but fails to resolve (FR-009), or when a module matches `GOPRIVATE` (FR-008) — the exact bug class issue #248 fixed for Cargo and 032/033 fixed for npm/PyPI.
- Widen the `deps-core` `Registry`/`EcosystemFormatter` **trait** surface — every hook this spec needs already exists generically from the Cargo/npm/PyPI work.

## 9. Open Questions

All blocking `[NEEDS CLARIFICATION]` items are resolved as of 2026-09-04:

- **Auth/credential handling**: resolved — reject any proxy hop URL with
  embedded userinfo, matching the Cargo/npm/PyPI precedent exactly
  (FR-009/FR-014). No `.netrc` detection or acknowledgment in phase 1;
  Go's broader credential conventions (`.netrc`, URL-embedded basic-auth)
  are entirely out of scope, owned by a dedicated future auth-handling
  spec, which is also the natural home for `GOPROXY`'s documented
  bare-local-filesystem-path entry form (no auth concept, but a related
  "hop needs validation beyond https-URL shape" surface — path traversal
  rather than credential handling).
- **Live environment-variable reading**: resolved — no concrete
  workspace/editor-launch demand signal exists for reading the LSP
  server's live process environment (`GOPROXY`/`GOPRIVATE` set by a
  devcontainer or CI wrapper); `gh issue list`/Dependi parity review
  surfaced no such request. File-based `$GOENV`-only is sufficient for
  phase 1, matching how npm/PyPI left their own live-env-var surfaces
  unscheduled rather than deferred to a tracked follow-up.
- **`direct` sentinel scope**: resolved by direct code inspection this
  session (see Assumptions) — `crates/deps-go/src/registry.rs` has no
  non-proxy, direct-VCS resolution path of any kind (only four methods,
  all built on the Go module-proxy-protocol client), and the workspace's
  closest analogue (`GithubActionsRegistry`'s tags client) is
  GitHub-specific and not reusable for Go's arbitrary-VCS `go-import`
  meta-tag discovery protocol. FR-006's `direct` support is confirmed as a
  fail-closed no-op in phase 1 — US-003 is achievable only partially (the
  fallback triggers correctly on proxy not-found, but yields no data
  rather than genuine direct-VCS-resolved data) until a follow-up
  implements actual direct-VCS resolution.

Non-blocking, deliberately deferred:

- Whether `GoProxyUrl` should eventually be consolidated with Cargo's
  `RegistryIndex`/npm's `NpmRegistryIndex`/PyPI's `PypiIndexUrl` into one
  `deps-core`-shared newtype is left for a later refactor once the
  duplication across four near-identical implementations is concrete,
  rather than speculatively generalizing now (matches this project's
  stated MVP/no-premature-abstraction principle).
- Checksum-database (`GOSUMDB`/`GONOSUMCHECK`) verification is out of scope
  entirely (see Out of Scope) rather than an open question — no ecosystem
  crate in this project does integrity verification today, so there is no
  precedent to extend.

## 10. See Also

- [[constitution]] — project principles (not yet created for this project; cross-check against `.claude/rules/*.md` instead)
- [[MOC-specs]] — all specifications
- [[023-cargo-custom-registries/spec|023-cargo-custom-registries]] — the original reference implementation pattern: `DependencySource::AlternateRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `EcosystemFormatter::can_resolve_source`, `deps_core::net_policy` host-classifier gating
- [[032-npm-npmrc-registry-support/spec|032-npm-npmrc-registry-support]] — closest file-based-config analogue: `.npmrc` parsing, per-file memoization pattern, the shared `registries.workspace_registries` policy key
- [[033-pypi-private-index-support/spec|033-pypi-private-index-support]] — closest multi-hop-chain analogue: `--extra-index-url`'s additive fallback semantics, the terminal-on-transport-failure rule (FR-005(c)), and the opaque routing-key widening of `AlternateRegistry.index`'s contract, both directly reused here for `GOPROXY`'s chain model
- `.local/testing/playbooks/competitive-parity.md` — "Private/alternative registry support" row naming Go (`GOPROXY`) as one of the originally-identified candidates, now the last of the four highest-demand ecosystems (Cargo/npm/PyPI/Go) to be spec'd
- Dependi private-registry demand evidence (different repository, links intentionally not auto-linked): `` github.com/filllabs/dependi/issues/18 ``
- `crates/deps-core/src/parser.rs` — `DependencySource`, `AlternateRegistry`, `CustomRegistry`, `is_version_resolvable`
- `crates/deps-core/src/registry.rs` — `Registry` trait, `get_versions_from`/`get_latest_matching_from`
- `crates/deps-core/src/net_policy.rs` — `HostClass`, `classify_host`, `RegistryAccessPolicy`, `WorkspaceRegistryAccess`
- `crates/deps-core/src/lsp_helpers/mod.rs` — `SourcePolicy` and the other six concern-scoped `EcosystemFormatter` supertraits (split by #515)
- `crates/deps-go/src/registry.rs` — `PROXY_BASE` (line 35), the hardcoded constant this spec replaces with an overridable chain
- `crates/deps-go/src/version.rs` — `escape_module_path`, `escape_version`, reused as-is for any resolved private proxy host (FR-010)
- Issue #248 — the Cargo silent-fallback-to-public-registry bug this spec's FR-009/US-006 explicitly avoid repeating for Go

---
aliases:
  - NuGet Private/Custom Feed Support
  - NuGet.Config packageSources Resolution
tags:
  - sdd
  - spec
  - research
  - enhancement
  - nuget
  - security
created: 2026-09-03
updated: 2026-09-04
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
  - "[[032-npm-npmrc-registry-support/spec|npm .npmrc Custom/Private Registry Support]]"
  - "[[033-pypi-private-index-support/spec|PyPI Private/Custom Index Resolution]]"
  - "[[034-go-goproxy-private-registry/spec|Go GOPROXY/GOPRIVATE Module Proxy Resolution]]"
---

# Feature: NuGet Private/Custom Feed Support (`NuGet.Config` `<packageSources>`)

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Issue**: [#523](https://github.com/bug-ops/deps-lsp/issues/523)
> **Branch**: (assign at implementation time, e.g. `feat/<issue>-nuget-private-feed-support`)
> **Priority**: P3
> **Type**: research/enhancement (competitive-parity gap)

## 1. Overview

### Problem Statement

`deps-nuget` only ever queries the public `api.nuget.org` v3 service index —
confirmed live this session by reading the crate directly:

- `crates/deps-nuget/src/registry.rs:18` hardcodes
  `const SERVICE_INDEX_URL: &str = "https://api.nuget.org/v3/index.json";`
  with no override mechanism of any kind.
- `crates/deps-nuget/src/lockfile.rs:29` independently hardcodes the same
  URL as `const NUGET_ORG_URL`, so even the lockfile-matching path has no
  private-feed awareness.
- No parsing exists anywhere in the crate of `NuGet.Config`'s
  `<packageSources>` / `<packageSourceCredentials>` / `<disabledPackageSources>`
  elements, and no environment-variable equivalent is read at all (unlike
  Go's `$GOENV`-file convention, NuGet has no analogous env-var surface
  worth naming here).

This gap is **already named inline** in the crate's own module
documentation, `crates/deps-nuget/src/ecosystem.rs:1-10`:

```
//! # Unknown/unresolvable packages
//!
//! Only `api.nuget.org` is queried — private feeds (`NuGet.config` `<packageSources>`,
//! Azure Artifacts, GitHub Packages, internal Artifactory) are out of scope (D4). A 404 or
//! otherwise-unknown package must degrade to **no diagnostic, no inlay hint, no error
//! marker** (S4) — this already falls out of `deps-lsp`'s generic error handling around
//! `Registry::get_latest_matching` ...
```

This references a design decision labeled "D4" (and a corresponding
behavioral contract "S4") as if both were already recorded somewhere, but
neither has a recoverable source spec: `specs/027-nuget-unlisted-version-and-multiproject-lockfile/`
(the most recent NuGet-focused spec in this tracked history, shipped via
PR #458 / issue #451) does not mention private feeds, and no other file
under `specs/` documents a "D4" decision for NuGet. No GitHub issue tracks
this as a scoped-out gap either. This matches a recurring pattern already
seen multiple times in this project's history (issues #441, #453, #462,
#521 all followed the same shape: a PR/module doc names a deferred
decision inline, and no tracking artifact is ever filed for it).

**Competitive evidence** (live-verified via
`gh issue view -R filllabs/dependi 291` this session): a real Dependi user
filed `` filllabs/dependi#291 `` ("Private NuGet Servers"), created
2026-03-05 and closed the same day, describing exactly this gap — a
company-internal BaGet feed that does not mirror nuget.org, so pointing
Dependi's "Index Server" setting at it just produces 404s. The reporter's
own closing comment: *"Nevermind. I just saw that private feeds are a paid
feature."* — i.e. Dependi's **free tier has the identical gap deps-lsp has
today**, and the fix is gated behind Dependi Pro rather than shipped to
everyone. This is the same free-vs-Pro competitive wedge that already
justified and shipped the Cargo
([[023-cargo-custom-registries/spec|023]]), npm
([[032-npm-npmrc-registry-support/spec|032]]), and PyPI
([[033-pypi-private-index-support/spec|033]]) private-registry work, and is
currently spec'd (not yet built) for Go
([[034-go-goproxy-private-registry/spec|034]]).

NuGet was **not** among the six previously-tracked Dependi private-registry
issues (`` #211 ``, `` #214 ``, `` #285 ``, `` #292 ``, `` #293 ``, `` #18 ``)
this project's continuous-improvement cycles have been checking
cycle-over-cycle — `` #291 `` is a newly surfaced **seventh** data point in
the same competitive theme, found by checking Dependi's NuGet-labeled
issues directly rather than relying on the previously-cached list of six.

`deps-cargo`, `deps-npm`, `deps-pypi`, and the (not-yet-built)
`deps-go` spec all establish and reuse a proven, generic pattern from
`deps-core` that this feature needs no `deps-core` trait change to adopt:

- `DependencySource::AlternateRegistry { index, mirrors_crates_io }`
  (`crates/deps-core/src/parser.rs`) — the source-agnostic "resolved to a
  concrete, fetchable feed" variant. `deps-nuget` would construct it
  directly (`mirrors_crates_io: false`).
- `DependencySource::CustomRegistry { url }` — the existing "present, but
  not resolved to a concrete, fetchable feed" fail-closed state.
  `is_version_resolvable()` is already `false` for it, so every existing
  fail-closed gate (hover, diagnostics, code actions) applies with zero new
  code.
- `Registry::get_versions_from` / `get_latest_matching_from` — defaulted
  trait methods any `Registry` impl can override; `NuGetRegistry` would
  override these exactly as `CargoRegistry`/`NpmRegistry`/`PypiRegistry` do.
- `EcosystemFormatter`'s `SourcePolicy` supertrait (one of the seven
  concern-scoped supertraits `EcosystemFormatter` was split into by #515;
  see `crates/deps-core/src/lsp_helpers/mod.rs`) and its
  `can_resolve_source` hook — the single override point gating
  hover/diagnostics/code-actions; `NuGetFormatter` would implement this
  exactly as the other ecosystems' formatters do.
- `deps_core::net_policy` (`HostClass`, `classify_host`,
  `RegistryAccessPolicy`, `WorkspaceRegistryAccess`) — the SSRF-hardening
  host classifier already gating Cargo's/npm's/PyPI's workspace-declared
  registries behind the shared `registries.workspace_registries` setting
  (`off` / `public_only` / `all`, default `public_only`). `deps-nuget`
  would reuse this same setting.

What `deps-nuget` needs on top of that shared foundation is NuGet-specific,
and materially more layered than any of the three shipped ecosystems (see
Open Questions below): parsing `NuGet.Config` XML `<packageSources>` /
`<clear/>` / `<disabledPackageSources>` elements, and following the
existing **two-hop** service-index indirection
(`crates/deps-nuget/src/registry.rs`'s `ServiceIndexResponse`/
`ServiceResource` types — a service-index JSON that itself points to
per-capability resource URLs such as `PackageBaseAddress`,
`SearchQueryService`, and `RegistrationsBaseUrl`) for every configured
source, not just the hardcoded public one.

> [!warning] Assumptions
> - A private feed referenced in `NuGet.Config` speaks the standard NuGet
>   V3 protocol (a service-index JSON resolving to `PackageBaseAddress` /
>   `SearchQueryService` / `RegistrationsBaseUrl` resources) that
>   `deps-nuget` already implements for `api.nuget.org` — Azure Artifacts,
>   GitHub Packages, JFrog Artifactory's NuGet repos, BaGet, and ProGet all
>   implement V3. A feed that only speaks the legacy V2 (OData) protocol is
>   out of scope, matching how the Cargo/npm/PyPI/Go specs each scoped out
>   non-standard-protocol registries.
> - `NuGet.Config` is an XML file (unlike `.npmrc`'s `KEY=VALUE` format or
>   Go's `$GOENV` format) — `<packageSources>` entries are `<add key="..."
>   value="..." />` elements, `<clear/>` resets any inherited source list,
>   and `<disabledPackageSources>` can turn an already-declared source off
>   without removing it. These are the authoritative semantics this spec's
>   Functional Requirements are built against (`nuget.exe`/`dotnet nuget`
>   config documentation).
> - Matching this project's existing single-file-scope precedent for
>   Cargo's `.cargo/config.toml` and npm's `.npmrc` (phase 1 for both
>   targeted the nearest project-local file only, not the full multi-level
>   merge), this spec's default assumption for phase 1 is a **project-local
>   `NuGet.Config`** discovered by walking upward from the manifest
>   (`.csproj`/`.fsproj`/etc.) toward the repository root — see Open
>   Questions for whether this is sufficient or whether the fuller
>   `nuget.exe` precedence chain (solution dir → user profile → machine-wide)
>   is needed for phase 1 to be useful in practice.

### Goal

A NuGet package dependency whose applicable feed is overridden via a
project-local `NuGet.Config` `<packageSources>` entry (Azure Artifacts,
GitHub Packages, an internal Artifactory/BaGet/ProGet instance) gets the
same hover/diagnostic/completion value a `nuget.org`-resolved dependency
gets today — with zero regression for projects declaring no override, and
with no credential ever read, stored, or transmitted in this phase (auth
wiring deferred, see Out of Scope).

### Out of Scope

> [!danger] Explicit Exclusions
> - **All auth/credential handling** —
>   `<packageSourceCredentials>` cleartext or encrypted `<add key="Username"
>   .../><add key="ClearTextPassword" .../>` blocks, Azure DevOps PAT-based
>   feeds, and GitHub Packages token auth. Phase 1 resolves *which* feed a
>   package belongs to and queries it unauthenticated; any source with an
>   associated `<packageSourceCredentials>` entry fails closed, matching the
>   Cargo/npm/PyPI/Go precedent exactly — it never reads, stores, or
>   transmits a credential. Unlike the three shipped ecosystems and the
>   Go spec, NuGet's `<packageSourceCredentials>` is a genuinely **new auth
>   config shape** for this project — an XML block of per-source credential
>   elements, not a token-in-URL or a `.npmrc`-style flat key. It is not
>   directly analogous to `.npmrc`'s `_authToken` or pip's netrc reliance,
>   so a dedicated follow-up spec should design its handling from scratch
>   rather than reuse an existing deferred-auth shape. `[NEEDS
>   CLARIFICATION: should the follow-up spec also address NuGet's
>   `ClearTextPassword` vs. `Password` (DPAPI-encrypted, Windows-only, not
>   portably decryptable) distinction now, or leave that entirely for
>   whoever picks up the follow-up?]`
> - **User-profile and machine-wide config tiers** (`%APPDATA%\NuGet\NuGet.Config`
>   / `~/.nuget/NuGet/NuGet.Config`, machine-wide config) — see the resolved
>   Open Questions below. **Narrowed during implementation**: the in-repo
>   ancestor chain itself (every `NuGet.Config` between the manifest and the
>   filesystem root) is now merged root-to-leaf and fully in scope (FR-001) —
>   only the tiers outside the repository remain excluded, deliberately
>   (that is where `<packageSourceCredentials>` most commonly lives, and a
>   global `<clear/>` there would silently re-route every project on the
>   machine).
> - **Checksum/signature verification** (NuGet package signing, `nuget.org`
>   trust chains) — no integrity verification exists in `deps-nuget` today,
>   or in any other ecosystem crate in this project; out of scope entirely,
>   matching the Go spec's identical exclusion of `GOSUMDB`.
> - **V2 (OData) protocol feeds** — phase 1 targets V3 service-index feeds
>   only, matching the Assumptions above.
> - **Package-name search/completion** for a feed that does not implement
>   `SearchQueryService` — same choice
>   [[032-npm-npmrc-registry-support/spec|032]]'s FR-011,
>   [[033-pypi-private-index-support/spec|033]]'s FR-014, and
>   [[034-go-goproxy-private-registry/spec|034]]'s FR-016 made:
>   unconditional no-op for alternate-feed-resolved dependencies rather than
>   a per-feed capability probe.
> - **A dedicated `NuGet.Config` file watcher** — same choice Cargo's
>   FR-013, npm's FR-016, PyPI's FR-012, and Go's FR-015 made: document
>   staleness (edits take effect on next reparse of the affected manifest)
>   rather than build a new watcher subsystem.
> - **`packages.config`-style legacy project format's own source
>   resolution quirks** beyond what already works for `nuget.org` — this
>   spec only extends *where* a source resolves to, not how the manifest
>   itself is parsed (`packages.config`/`PackageReference`/central package
>   management are all already handled upstream of the registry layer per
>   [[027-nuget-unlisted-version-and-multiproject-lockfile/spec|027]]).

## 2. User Stories

### US-001: `<packageSources>` feed resolution

AS A developer whose company routes NuGet package traffic through an
internal Artifactory/BaGet/ProGet feed
I WANT dependencies in my `.csproj`/`Directory.Packages.props` to resolve
against that feed
SO THAT hover/diagnostics reflect what my feed actually serves (which may
differ from, extend, or entirely replace `nuget.org`)

**Acceptance criteria:**
```
GIVEN a project-local NuGet.Config containing
      <packageSources>
        <clear />
        <add key="CorpFeed" value="https://nuget.mycorp.example/v3/index.json" />
      </packageSources>
WHEN I hover over any dependency declared in the project file
THEN the hover reflects CorpFeed's data, resolved through its own
     service-index -> PackageBaseAddress/RegistrationsBaseUrl indirection,
     and no request is sent to api.nuget.org
```

### US-002: Additive feeds (no `<clear/>`)

AS A developer whose `NuGet.Config` adds a private feed alongside the
default `nuget.org` source (no `<clear/>`)
I WANT packages available on either feed to resolve correctly
SO THAT adding an internal feed for a handful of private packages doesn't
break resolution for the majority of packages that still come from
`nuget.org`

**Acceptance criteria:**
```
GIVEN a NuGet.Config containing
      <packageSources>
        <add key="CorpFeed" value="https://nuget.mycorp.example/v3/index.json" />
      </packageSources>
  (no <clear/>, so nuget.org remains implicitly present per NuGet's own
   default-source-preservation behavior)
WHEN I hover over a package present only on CorpFeed, and separately over
     a package present only on nuget.org
THEN both resolve correctly, each via its own feed
```

### US-003: `<disabledPackageSources>` respected

AS A developer who has temporarily disabled a configured source via
`<disabledPackageSources>`
I WANT the LSP to skip that source entirely
SO THAT the LSP's behavior matches what `dotnet restore` would actually do
in this environment

**Acceptance criteria:**
```
GIVEN a NuGet.Config declaring CorpFeed in <packageSources> and also
      disabling it via
      <disabledPackageSources>
        <add key="CorpFeed" value="true" />
      </disabledPackageSources>
WHEN I hover over a dependency that would otherwise resolve via CorpFeed
THEN CorpFeed is not queried, and the dependency falls back to any other
     enabled source, or resolves as unknown if none remain
```

### US-004: No regression for projects declaring no override

AS A developer with no `NuGet.Config` file, or one that declares no
`<packageSources>` override
I WANT the LSP to keep behaving exactly as it does today
SO THAT this feature introduces zero risk for the overwhelming majority of
.NET projects

**Acceptance criteria:**
```
GIVEN no project-local NuGet.Config exists, or it exists but declares no
      <packageSources> override
WHEN I hover over any dependency
THEN the hover is byte-identical to pre-feature behavior (api.nuget.org)
```

### US-005: Unresolved/misconfigured feed fails closed

AS A developer whose `NuGet.Config` references an unreachable, invalid, or
policy-blocked feed URL
I WANT the LSP to show no data for dependencies routed to it rather than
silently checking `nuget.org` instead
SO THAT I never mistake a stale/wrong public-feed result for my private
feed's actual state

**Acceptance criteria:**
```
GIVEN a NuGet.Config source value that is not a well-formed URL, or is
      blocked by the workspace-registry access policy
WHEN I hover over a dependency routed to that source
THEN no version data is shown, and no request is sent to api.nuget.org for
     that dependency (mirrors the regression class issue #248 fixed for
     Cargo and the equivalent classes 032/033 closed for npm/PyPI)
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL locate every in-repo `NuGet.Config` ancestor file by walking upward from the manifest's directory toward the filesystem root (cap 64 directories), checking `["NuGet.Config", "nuget.config", "NuGet.config"]` per directory, and SHALL merge every file found **root-to-leaf** — not "nearest file wins" — accumulating `<packageSources>`/`<disabledPackageSources>`/`<packageSourceCredentials>`/`<packageSourceMapping>` across the whole chain. **Corrected during implementation** (superseding the original "nearest file wins" draft): a root `<clear/>` must stay in effect for every descendant project even when a leaf file adds a feed without repeating `<clear/>` — nearest-wins would silently resurrect the public hop the root explicitly cleared, reproducing the #248 bug class this feature exists to close. No user-profile/machine-wide tier is read (Open Questions, resolved below) | must |
| FR-002 | THE SYSTEM SHALL parse `<packageSources>` `<add key="..." value="..." />` entries in document order, and SHALL honor a `<clear/>` element by discarding every source accumulated so far in the FR-001 walk; `cleared` is **sticky** for the remainder of the root-to-leaf walk — once set, a later file's `<add>` with no `<clear/>` of its own does not resurrect the implicit `nuget.org` tail | must |
| FR-003 | WHEN the merged FR-001/FR-002 chain contains no `<clear/>` THE SYSTEM SHALL treat the declared sources as additive to the existing default `api.nuget.org` source, matching `nuget.exe`'s own default-source-preservation behavior (US-002) | must |
| FR-004 | THE SYSTEM SHALL parse `<disabledPackageSources>` `<add key="..." value="..." />` entries (value compared case-insensitively against `"true"`) and exclude the matching named source from resolution entirely (US-003), regardless of its position in `<packageSources>` — key matching goes through the FR-009 union funnel | must |
| FR-005 | WHEN no in-repo `NuGet.Config` is found, or the merged chain declares no `<packageSources>` override THE SYSTEM SHALL use the existing hardcoded `api.nuget.org` behavior unchanged — this is the existing `SERVICE_INDEX_URL`/`NUGET_ORG_URL` behavior, now expressed as the default of an overridable source list rather than an unconditional constant | must |
| FR-006 | THE SYSTEM SHALL resolve each configured source through the existing two-hop service-index indirection (`ServiceIndexResponse`/`ServiceResource` in `crates/deps-nuget/src/registry.rs`) identically for a private feed as for `api.nuget.org` — no separate resolution code path for alternate feeds. The service index's `@type` field SHALL tolerate a JSON-LD array or a malformed non-string scalar (degrading the resource to "matches nothing" rather than failing the whole document), and a `protocolVersion="2"` source SHALL be rejected as an explicit unsupported-protocol reason at config-parse time rather than surfacing as a confusing missing-resource error later | must |
| FR-007 | WHEN a package is absent from one configured source (an explicit not-found response, or an empty version listing) and additional enabled sources remain (per FR-003) THE SYSTEM SHALL attempt resolution against the next configured source. A transport failure (connection error, timeout, 5xx) on a source SHALL be treated as terminal for that source — reported as `DepsError::ChainResolutionHalted`, not silently skipped in favor of a fallback the user did not request for the reachability state they are actually in — mirroring PyPI's FR-005(c) precedent (033) and Go's FR-005 (034) | must |
| FR-008 | WHEN a `<packageSources>` entry's `value` fails validation (non-https, contains userinfo, not a well-formed URL, a local/UNC filesystem path, or `protocolVersion="2"`) or is blocked by FR-010's policy THE SYSTEM SHALL treat that entry as invalid: represent the affected package's source as `DependencySource::CustomRegistry` if it is the only remaining viable source (or if the merged chain's `<clear/>` state leaves zero usable hops at all, per the R4 correction below), or drop the invalid entry and continue with the remaining valid sources otherwise — mirroring PyPI's FR-006 (033) and Go's FR-009 (034) per-entry-fail-closed rule, logging a `tracing::warn!` (or `debug!` for a legitimate-but-unsupported local-feed/V2 shape) naming the raw value, and SHALL NOT fall back to `api.nuget.org` for a package whose resolution the user explicitly overrode via `<clear/>`. **R4 correction**: a merged chain whose `<clear/>` state removes every source down to zero — whether or not there is an invalid entry left to name — is an explicit fail-closed `CustomRegistry` state (a distinct sentinel when no entry can be named), never a silent fall-through to plain `Registry` | must |
| FR-009 | THE SYSTEM SHALL detect a `<packageSourceCredentials>` block associated with a configured source and treat that source as invalid per FR-008 (fails closed, never attempts unauthenticated access to a feed the user has configured credentials for) rather than silently attempting an anonymous request against it. **Corrected during implementation**: source-key matching (for both `<disabledPackageSources>` and `<packageSourceCredentials>`) is case-insensitive and additionally compares against the XML-name-decoded form of a `<packageSourceCredentials>` child element name (NuGet XML-encodes non-alphanumerics there, e.g. `<Corp_x0020_Feed>` for a source named `Corp Feed`) — a union of the raw-lowercased and decoded-lowercased candidates on both sides of the comparison, since exact-only matching left FR-004/FR-009 failing open on a case or encoding mismatch | must — security-relevant, not merely functional |
| FR-010 | THE SYSTEM SHALL classify every explicitly-declared `<packageSources>` entry's host through `deps_core::net_policy::classify_host` and gate the fetch behind the existing shared `registries.workspace_registries` setting (`off` / `public_only` / `all`, default `public_only`) — the same setting Cargo/npm/PyPI already gate on, reused as-is with no new `nuget.*` key. The default `api.nuget.org` source used when `NuGet.Config` declares no override is never subject to this gate — it is the same ungated public-tier client `deps-nuget` already uses today. Additionally (resolving the net_policy second-hop Open Question, see below), a workspace-declared feed's own resolved service-index resource URLs (`PackageBaseAddress`/`SearchQueryService`/`RegistrationsBaseUrl`) are re-validated against this same policy before being trusted: a rejected `PackageBaseAddress` fails the whole feed, a rejected `RegistrationsBaseUrl`/`SearchQueryService` degrades to absent | must |
| FR-011 | THE SYSTEM SHALL add `NuGetFormatter`'s implementation of the `SourcePolicy` supertrait's `can_resolve_source` hook (overriding the existing defaulted `EcosystemFormatter::can_resolve_source`) so hover/diagnostics/code-actions correctly gate on a resolved `AlternateRegistry` source — no `deps-core` trait change required. **4th correction (M1, added during implementation)**: `NuGetFormatter` SHALL also override `PackageRendering::suppress_package_url` to omit the nuget.org package-page link for any dependency that is not `source_is_public_registry_content` — otherwise a nuget.org link would render alongside live private-feed data, reading as false confirmation the link is real | must |
| FR-012 | THE SYSTEM SHALL add `Registry::get_versions_from` / `get_latest_matching_from` overrides on `NuGetRegistry`, routing fetches for `AlternateRegistry`-sourced dependencies to the resolved source list instead of unconditional `SERVICE_INDEX_URL` — reuses the existing defaulted `deps-core::Registry` trait methods | must |
| FR-013 | **Corrected during implementation** (the original draft misread the call graph): `crates/deps-nuget/src/lockfile.rs`'s `NUGET_ORG_URL` constant feeds only the informational `ResolvedSource::Registry.url` field, which nothing in `deps-lsp`/`deps-core::lsp_helpers` reads and which triggers no network request — there is no silent-mismatch risk to fix. THE SYSTEM SHALL dedupe the constant (`registry.rs`'s `NUGET_ORG_INDEX_URL` becomes the single source of truth, referenced by `lockfile.rs`) rather than thread FR-001's config resolution into the lockfile-matching path | must |
| FR-014 | THE SYSTEM SHALL NOT read, log, or transmit any credential value from a `<packageSourceCredentials>` block — detection per FR-009 SHALL identify that a credential block exists (by source key) without parsing its `Username`/`ClearTextPassword`/`Password` child values into any retained field, so no code path ever holds a credential value in memory | must — security-blocking |
| FR-015 | THE SYSTEM SHALL document `NuGet.Config` staleness as a known limitation (edits take effect on next reparse of the affected manifest) rather than add a dedicated file watcher, mirroring Cargo's FR-013, npm's FR-016, PyPI's FR-012, and Go's FR-015 resolution | must — the choice itself, not a specific mechanism, is mandatory |
| FR-016 | Package-name search/completion for a dependency resolved to a non-default source without a working `SearchQueryService` resource SHALL no-op rather than error or query `api.nuget.org`. `complete_package_names` itself stays source-blind (the typed string is a prefix, not a resolved private id) and always queries `api.nuget.org`, mirroring 032's FR-011, 033's FR-014, and 034's FR-016 | must |
| FR-017 | **5th correction, added during implementation** — absent from the original spec entirely: THE SYSTEM SHALL parse `<packageSourceMapping>` (`<packageSource key="..."><package pattern="..." /></packageSource>`, NuGet 6.0+'s recommended dependency-confusion defense) and, when present with at least one pattern, route every dependency through it instead of the FR-002/FR-003 chain. Matching is case-insensitive against a bare `*`, a trailing-`*` prefix glob, or an exact id; the longest/most-specific match wins (exact beats prefix regardless of character length, longer prefix beats shorter), and a tie makes every tied pattern's source keys eligible. A package matching no pattern becomes `CustomRegistry` (fail closed — real NuGet fails restore with NU1100 in this case, never falls through to an unmapped registry). A package whose winning pattern resolves only to the real `nuget.org` source (identified by normalized URL, never by a source's `key` — see FR-010's second-hop URL comparison) resolves to plain `Registry`, preserving OSV/deps.dev/hover-trust signals; otherwise it resolves to an `AlternateRegistry` chain with `implicit_public_fallback: false` **unconditionally** — the mapping is authoritative and never appends the public hop even when `<clear/>` is absent, which is the dependency-confusion leak this FR exists to close. **Merge strategy (R1, resolving a critic-caught defect in an earlier draft of this correction)**: mapping rules are merged root-to-leaf across every ancestor file (grouped by pattern, accumulating every source key that ever named it), never "nearest file wins" — a root mapping `{CorpFeed: MyCompany.*, nuget.org: *}` combined with a leaf mapping `{nuget.org: *}` must still route `MyCompany.Internal` to CorpFeed; taking the leaf's `*` alone would leak the private id to nuget.org, the exact attack this FR exists to prevent. A mapping key's resolution to a declared `<packageSources>` entry goes through the same FR-009 union key-matching funnel, but **unlike** FR-004/FR-009's exclusion-set matching, an ambiguous union match here (resolving to more than one distinct declared source) is treated as unresolvable and contributes nothing — growing an *inclusion* set on a union match is fail-open, not fail-closed. **S1 correction (impl-critic)**: a mapping key that is the literal `nuget.org` and resolves to **no** declared `<packageSources>` entry falls back to the real public feed rather than contributing nothing — the near-universal real-world shape is a `<packageSourceMapping>` naming `nuget.org` for its `*` pattern while `nuget.org` itself lives in the machine/user-profile config this feature deliberately never reads; without this, every public package in such a project would fail closed project-wide. This does not weaken FR-010's URL-identification rule: that rule governs a source that **is** declared and might be lying about its identity, not a key with no declared entry to spoof | must — security-relevant |
| FR-018 | **6th correction, added during implementation (S4, impl-critic)** — absent from the original spec entirely: THE SYSTEM SHALL parse `<packageSources><remove key="..."/></packageSources>` and exclude the matching accumulated source (via the same FR-009 union key funnel), applied per-file after that file's own `<add>`s during the FR-001 root-to-leaf accumulation. `<remove key="nuget.org"/>` additionally suppresses the implicit public tail hop (sticky across the remaining walk, same rationale as `<clear/>`), so an explicitly removed public source cannot be resurrected as the implicit default — without this, `<remove>` was silently unparsed and an explicitly removed source (public or private) stayed reachable, the #248 bug class in the opposite direction. `<packageSourceMapping><clear/>` is explicitly **out of scope**: mapping rules are unconditionally merged root-to-leaf (FR-017/R1) and never reset by a leaf-level `<clear/>` — a documented scope cut, not an oversight, since undoing R1's merge for this one element needs its own empirical verification against real NuGet before it can be added safely | must — security-relevant |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No credential-shaped value (`<packageSourceCredentials>` child element content, URL userinfo) is ever parsed into a retained field, held in memory beyond the immediate detection check, logged, or transmitted in phase 1 — verified by a structural test asserting the parsed config type has no field capable of holding such a value, matching the pattern Cargo's NFR-001, npm's NFR-001, PyPI's NFR-001, and Go's NFR-001 established |
| NFR-002 | Security | Every resolved `<packageSources>` entry URL is validated (https-only, no userinfo, with the same test-only loopback carve-out precedent as Cargo/npm/PyPI/Go) and normalized before any network request — this applies to the top-level configured feed URL, and, per FR-010's resolution of the net_policy second-hop question, also to the resolved `PackageBaseAddress`/`SearchQueryService`/`RegistrationsBaseUrl` resource URLs returned by a workspace-declared feed's own service index |
| NFR-003 | Security | Three residual risks, all stated for security-reviewer sign-off. **(1) Inbound reachability**: an unauthenticated HTTPS GET to a workspace-declared feed still occurs, which is reachability into the user's internal network usable for existence probing by a hostile repository — mitigated identically to Cargo/npm/PyPI/Go by `registries.workspace_registries` defaulting to `public_only`. **(2) Two-hop indirection**: unlike Cargo/npm/PyPI's single-URL registries, a NuGet feed's service index can itself redirect a validated top-level host to an arbitrary second-hop resource URL (`PackageBaseAddress` et al.) — resolved by FR-010's per-`@id` `validate_index_url` re-check for a workspace-declared feed (this Open Question is now closed, see below). **(3) Origin-pinning loss for alternate feeds**: the flat-container fetch for the default `api.nuget.org` source uses `HttpCache::get_cached_trusted_origin`, which stops any redirect leaving the resolved `PackageBaseAddress` prefix; a workspace-declared feed instead routes through `HttpCache::get_cached_workspace` (needed for FR-010's live per-redirect-hop policy re-check), which permits a redirect to any other `Global`-classified host under `public_only` — a data-fidelity risk (a redirected response could differ from what the configured feed itself would have served), not a credential-exfiltration one, since no credential is ever attached in phase 1. Combining origin-pinning with the workspace-policy guard needs a policy-tiered, purge-on-policy-change `trusted_clients` pool in `HttpCache` that does not exist today (`Transport::origin_pinned` hardcodes `AddrGuard::Baseline`); tracked as a follow-up ("policy-tiered origin-pinned transport in `HttpCache`"), not a phase-1 blocker — the same reduction phase 1 already accepts for registration-hive enrichment (publish times, hover-only unlisted markers), which is skipped entirely for alternate feeds for the identical root-cause reason |
| NFR-004 | Performance | No additional filesystem/network activity for a project declaring no `NuGet.Config` override, or a `NuGet.Config` that declares neither `<packageSources>` nor `<disabledPackageSources>` — zero regression path, verified by existing test suite |
| NFR-005 | Reliability | Zero behavior change for any project declaring no `<packageSources>`/`<disabledPackageSources>` override — verified by the existing `deps-nuget` test suite producing unchanged results |
| NFR-006 | Maintainability | FR-003's additive-source rule, FR-004's disabled-source exclusion, and FR-007's fallback ordering are each verified by dedicated tests: (a) an additive source resolves alongside the implicit default; (b) a disabled source is never queried even though declared; (c) a transport failure on a source is terminal, not silently skipped |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencySource::AlternateRegistry` | Existing `deps-core` variant, reused as-is — the FR-002/FR-006 resolved state | `index: String` — for NuGet, an opaque routing key identifying the resolved source (mirrors PyPI's `ResolvedChain::key` / Go's `GoProxyChain` routing-key precedent for multi-source ecosystems), `mirrors_crates_io: bool` (always `false`) |
| `DependencySource::CustomRegistry` | Existing `deps-core` variant, reused as NuGet's FR-008 fail-closed state — no new variant introduced | `url: String` — the raw value as written; `is_version_resolvable()` already `false` |
| `NuGetConfig` | New `deps-nuget` type (`crates/deps-nuget/src/config.rs`) — the merged, root-to-leaf-accumulated view of every in-repo `NuGet.Config` ancestor file | `sources: Vec<PackageSourceEntry>` (post-accumulation, post-remove/disabled/credentialed-filtering), `cleared: bool` (sticky across the FR-001 walk), `nuget_org_removed: bool` (sticky, FR-018's `<remove key="nuget.org"/>`), `mapping: PackageSourceMapping` (FR-017) |
| `PackageSourceEntry` | New `deps-nuget` type — one resolved `<packageSources>` entry after accumulation | `key: String` (as declared; every comparison against it goes through the FR-009 union funnel), `value: Result<NuGetFeedUrl, InvalidEntry>` |
| `PackageSourceMapping` | New `deps-nuget` type (5th correction, FR-017) — merged `<packageSourceMapping>` rules | `patterns: Vec<(String, Vec<String>)>` — normalized pattern -> every source key that ever named it across the ancestor chain (R1's merge) |
| `NuGetFeedUrl` | Validated, normalized feed URL newtype, new and `deps-nuget`-local (mirrors `RegistryIndex`/`NpmRegistryIndex`/`PypiIndexUrl`/`GoProxyUrl` rather than promoting a shared type, per the same "wait for a third+ near-identical implementation" principle 033/034 applied — this would be the fifth) | https-only, no userinfo |
| `InvalidEntry` | New `deps-nuget` type — a present-but-unusable source entry, carrying what FR-008 needs to build `CustomRegistry` and to warn | `raw: String` (as written, userinfo-redacted), `reason: NuGetFeedUrlError` (validation failure kind — `HasCredentials`/`Disabled`/`UnsupportedProtocolVersion`/`LocalFeedUnsupported` alongside the shared `IndexUrlError` variants) |
| `NuGetSourceChain` | New `deps-nuget` type (mirrors `deps_pypi::config::ResolvedChain`) — one fully-resolved routing chain | `key: String` (hashed identity — `resolve_source_for` and `resolved_chains` recompute it independently and must agree), `hops: Vec<NuGetFeedUrl>`, `implicit_public_fallback: bool` (always `false` for an FR-017 mapping-derived chain) |
| `NuGetDependency::source` | New field on the existing manifest-dependency type (hand-written `Dependency` impl, not `impl_dependency!` — the macro's `source: $source:expr` arm cannot express `self.source.clone()`) | `DependencySource`, stamped by `NuGetEcosystem::parse_manifest` after parsing (parsers in `parser.rs` stay config-blind) |
| `NuGetRegistry` | Existing `deps-nuget` `Registry` impl, extended into a multi-source-aware router mirroring `PypiRegistry`'s `fallback_chain`/`alternates` structure (033) | `+ tier: NuGetRegistryTier` (`Public`/`WorkspaceDeclared`), `+ policy: Arc<RegistryAccessPolicy>`, `+ alternates: Arc<DashMap<String, Arc<Self>>>` (root-owned only), `+ fallback_chain: Vec<Arc<Self>>` |
| `Registry::get_versions_from` / `get_latest_matching_from` | Existing defaulted `deps-core::Registry` trait methods | Overridden by `NuGetRegistry`, no signature change |
| `EcosystemFormatter`'s `SourcePolicy` supertrait / `can_resolve_source` | Existing defaulted `deps-core` trait method (part of the seven-supertrait split from #515) | Implemented/overridden by `NuGetFormatter`, no signature change |
| `PackageRendering::suppress_package_url` | Existing defaulted `deps-core` trait method (4th correction, FR-011/M1) | Overridden by `NuGetFormatter` |

### 5a. Known Limitations (added during implementation)

- **OSV/deps.dev/hover-trust signal suppression for `AlternateRegistry` dependencies.**
  `SourcePolicy::source_is_public_registry_content` defaults to `Registry`-only,
  so any dependency resolved to an `AlternateRegistry` chain loses OSV
  vulnerability scanning, the deps.dev supply-chain signal, and the hover
  trust badge. This is deliberate privacy protection (reusing a weaker
  resolvability check there would send a private package's name and version
  to deps.dev by default), and FR-017's `<packageSourceMapping>` support
  substantially narrows its blast radius: with a mapping declared, only
  genuinely-private ids (those that don't resolve to the real `nuget.org`
  source) lose the signals. **Without** a mapping, NuGet's additive-by-default
  model means the mere presence of one extra `<add>` (no `<clear/>` needed)
  suppresses these signals for every dependency in the project, including
  ones still resolving from `api.nuget.org` via the implicit fallback hop —
  more likely to trigger than the equivalent PyPI precedent (033), since
  adding one internal feed is the common real-world case. Accepted as
  consistent with PyPI's identical trade-off, not a regression.
- **Origin-pinning loss / publish-time and hover-unlisted-marker loss for
  alternate feeds** — see NFR-003(3).
- **`<packageSourceMapping><clear/>` is not honored** (FR-018) — mapping rules
  accumulate root-to-leaf and are never reset, even by a leaf file's own
  `<clear/>` inside that element. This is the correct direction for R1's
  security-critical merge fix (a leaf `<clear/>` must not be usable to silently
  discard an ancestor's private-routing mapping either), but means a project
  that genuinely wants a leaf subproject to opt out of an inherited mapping
  cannot do so today. Deliberately deferred pending empirical verification
  against real NuGet (`dotnet nuget list source` on a two-level fixture) before
  changing R1's merge semantics for this one element.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| No `NuGet.Config` file, or it exists but declares no `<packageSources>`/`<disabledPackageSources>` | Byte-identical to today's behavior (US-004) |
| `<packageSources><clear/><add key="CorpFeed" value="https://nuget.mycorp.example/v3/index.json" /></packageSources>` | Every dependency routes to CorpFeed only; `api.nuget.org` is never queried (FR-002, US-001) |
| `<packageSources><add key="CorpFeed" value="..." /></packageSources>` (no `<clear/>`) | CorpFeed and the implicit default `api.nuget.org` both resolve (FR-003, US-002) |
| `<disabledPackageSources><add key="CorpFeed" value="true" /></disabledPackageSources>` (CorpFeed is the only declared source, no `<clear/>`) | CorpFeed excluded from resolution (FR-004, US-003); **S3 correction**: with no `<clear/>` in effect, this degrades to the implicit default `api.nuget.org`, matching FR-003's additive-source model exactly as if CorpFeed had never been declared at all — not `CustomRegistry`. Only a chain with `<clear/>` in effect (so there is no implicit tail to fall back to) turns a disabled/credentialed-to-zero state into `CustomRegistry` (FR-008's R4 correction) |
| `<packageSourceCredentials><CorpFeed><add key="Username" .../></CorpFeed></packageSourceCredentials>` present for a declared source | That source treated as invalid per FR-008/FR-009 — never queried unauthenticated, no credential value read into memory (FR-014). Same additive-vs-`<clear/>` distinction as the disabled-source row above governs what the *rest* of the chain resolves to |
| `<add key="Bad" value="not-a-valid-url" />` (sole remaining source, `<clear/>` in effect) | Source becomes `CustomRegistry { url: "not-a-valid-url" }`; warn logged; no `api.nuget.org` fallback (FR-008, US-005) |
| `<add key="Bad" value="not-a-valid-url" />` alongside another valid source | Invalid entry dropped (warn logged); resolution proceeds via the remaining valid source (FR-008) |
| Package absent from a configured private source, present on `api.nuget.org` (additive, no `<clear/>`) | Resolved via `api.nuget.org` after the private source's explicit not-found response (FR-007) |
| A configured source is unreachable (connection error/timeout) with further sources declared | Resolution halts at that source rather than silently skipping to the next — a distinguishable outcome, not a generic failure (FR-007, mirrors PyPI's 033 FR-005(c) / Go's 034 FR-005 trade-off) |
| `workspace_registries = off`, `NuGet.Config` declares a private source | That source is blocked by FR-010's policy → dropped/fails closed per FR-008, same as an invalid entry |
| `NuGet.Config` edited after initial resolution | Stale until the affected manifest is next reparsed (FR-015, documented limitation) |
| A workspace-declared feed's service index resolves `PackageBaseAddress` to an internal-network host | Resolution of that hop fails per FR-010's per-`@id` policy check, failing the whole feed closed (`CustomRegistry`) — never fetched |
| A workspace-declared feed's service index resolves `SearchQueryService`/`RegistrationsBaseUrl` to an internal-network host | That one resource degrades to absent (search no-ops per FR-016; freshness/hover-unlisted enrichment is unavailable), the feed as a whole still resolves normally via `PackageBaseAddress` |
| Lockfile matching (`packages.lock.json`) for a package resolved via a private source | Must use the same resolved source list as hover/diagnostics (FR-013) — a stale `NUGET_ORG_URL`-only lockfile path would silently mismatch a private-feed-resolved package's lockfile-pinned version against public `nuget.org` data |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Private-feed dependency (via `<packageSources>`) shows live hover/diagnostic/completion data | Pass on a real or mocked Azure Artifacts/BaGet-shaped fixture |
| SC-002 | Credentialed source is never queried unauthenticated, and no credential value is ever held in memory | Structural test per NFR-001/FR-014, plus a behavioral test asserting zero requests to a `<packageSourceCredentials>`-guarded source |
| SC-003 | Zero regression on projects declaring no `NuGet.Config` override | Every existing `deps-nuget` test produces unchanged results |
| SC-004 | Misconfigured/unreachable source never silently falls back to `api.nuget.org` ahead of a valid remaining/declared source | Test mirroring the #248/032/033/034 regression pattern, adapted for NuGet's additive-source model |

**SC-005 dropped during implementation**: the original criterion assumed the lockfile path threads live config resolution and must agree with the registry path on "which source a package resolves through". Verified false: `lockfile.rs`'s `NUGET_ORG_URL` (now deduped to `registry.rs`'s `NUGET_ORG_INDEX_URL`) feeds only the informational `ResolvedSource::Registry.url` field, which nothing downstream reads and which triggers no network request — see FR-013's correction. There is nothing for this criterion to test.

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features` before considering a task complete.
- Follow the Registry Integration Gate (`.claude/rules/continuous-improvement.md`) — verify against a real or mocked private NuGet V3 feed before filing the implementation PR.
- Update `CHANGELOG.md`, `ECOSYSTEM_GUIDE.md`, `.local/testing/coverage.md` (NuGet row), `.local/testing/playbooks/nuget.md` (create if absent), `.local/testing/regressions.md`.
- Reuse `DependencySource::AlternateRegistry`/`CustomRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `SourcePolicy`'s `can_resolve_source`, `deps_core::net_policy`, and the existing `ServiceIndexResponse`/`ServiceResource` two-hop resolution as-is rather than adding parallel `deps-nuget`-only mechanisms.
- File a GitHub issue tracking the original "D4"/"S4" deferred-scope decision as historical record once this spec exists, per the Prior Art note below — this spec is that decision's first tracked artifact.

### Ask First
- Any decision that touches auth/credential handling (`<packageSourceCredentials>`, DPAPI-encrypted `Password`) — explicitly out of scope for this spec; a dedicated follow-up spec owns NuGet's own credential-config shape.
- Implementing the multi-level config merge (solution-dir → user-profile → machine-wide) — explicitly deferred pending the Open Questions resolution below.
- Consolidating `NuGetFeedUrl` with Cargo's `RegistryIndex`/npm's `NpmRegistryIndex`/PyPI's `PypiIndexUrl`/Go's `GoProxyUrl` into a shared `deps-core` type — a cross-crate refactor beyond this spec's own file scope.

### Never
- Parse, log, or transmit any credential-shaped value (`<packageSourceCredentials>` child content, URL userinfo) in this phase (FR-014).
- Fall back to `api.nuget.org` when an explicit `<clear/>`+`<packageSources>` override is present but resolves to zero usable hops (FR-008/R4) — the exact bug class issue #248 fixed for Cargo and 032/033/034 fixed for npm/PyPI/Go. **S3 correction**: this "never" is scoped to a chain with `<clear/>` in effect. A source disabled via `<disabledPackageSources>` (FR-004) or credentialed (FR-009) with **no** `<clear/>` in the chain correctly degrades to the implicit `api.nuget.org` default per FR-003's additive-source model — the same answer as if that source had simply never been declared. This is not the #248 bug class: #248 was a `<clear/>` override being silently ignored, not an additive config's own already-implicit default staying implicit.
- Widen the `deps-core` `Registry`/`EcosystemFormatter` **trait** surface — every hook this spec needs already exists generically from the Cargo/npm/PyPI/Go work.
- Leave `crates/deps-nuget/src/lockfile.rs`'s `NUGET_ORG_URL` constant as a stale, unconverted duplicate once `registry.rs`'s `SERVICE_INDEX_URL` gains override support (FR-013).

## 9. Open Questions (all resolved)

- **Auth/credential handling — resolved: fail closed, no follow-up spec scheduled yet.**
  `<packageSourceCredentials>` is parsed for child element names only (into a
  set), never for `Username`/`ClearTextPassword`/`Password` values — any
  named source becomes `InvalidEntry { reason: HasCredentials }`, fail
  closed (FR-009/FR-014). `%VAR%`-style expansion is deliberately not
  implemented: an unexpanded placeholder value fails URL validation and
  fails closed naturally, so phase 1 needs zero code for it. The follow-up
  spec's scope, when someone picks it up, should cover `ClearTextPassword`
  plus NuGet credential providers only — **DPAPI-encrypted `Password` is
  permanently out of scope**, not merely deferred (Windows-only, requires
  `CryptUnprotectData`; deps-lsp must never decrypt a credential blob). Not
  scheduled as of this implementation.
- **Config discovery scope — resolved: in-repo upward walk, root-to-leaf
  accumulation across every ancestor file found, no user-profile/machine
  tier.** Superseding the original "nearest file wins" draft (FR-001):
  discovery still walks from the manifest's directory toward the filesystem
  root (cap 64), but now collects **every** `NuGet.Config` it finds and
  applies them in root-to-leaf order, with `cleared` sticky across the
  whole walk — this is what makes a root `<clear/>` survive a leaf file
  that adds a feed without repeating it (the C1 fix, closing the specific
  #248-shaped bug the original "nearest file wins" draft would have
  reproduced). The user-profile tier (`%APPDATA%\NuGet\NuGet.Config` /
  `~/.nuget/NuGet/NuGet.Config`) is still not read — deliberately, on
  purpose: that is exactly where `<packageSourceCredentials>` most commonly
  lives and where a global `<clear/>` would silently re-route every project
  on the machine, an escalation that belongs with the auth follow-up, not
  this phase. This is inconsistent with npm's `~/.npmrc` tier (npm does
  read the user tier, simply never parsing auth keys from it) — accepted as
  a deliberate scope cut since it degrades safely (extra `api.nuget.org`
  queries, never wrong data), not a gap.
- **net_policy second-hop coverage — resolved: yes, required, and now
  implemented (FR-010).** `HttpCache::get_cached_workspace`'s own doc states
  it does not re-check the initial request URL's host class, only
  DNS-resolved addresses and redirect hops — and `classify_addr` can never
  produce `HostClass::InternalName`, so a workspace-declared feed's *name*
  resolving to an internal address at the service-index-resource level
  would otherwise slip past the top-level gate. `ServiceIndex::resolve` now
  runs `validate_index_url(id, id, "nuget", PolicyGate::Enforce(policy))`
  on each picked resource `@id`, for workspace-declared feeds only (the
  default `api.nuget.org` keeps `PolicyGate::Skip` per FR-010's carve-out).
  A rejected `PackageBaseAddress` fails the whole feed (fail closed); a
  rejected `RegistrationsBaseUrl`/`SearchQueryService` degrades to absent —
  the same degradation an omitted resource already receives. See NFR-003(2)
  (resolved) and NFR-003(3) (the accepted origin-pinning-loss follow-up
  this fix's transport choice implies).

Non-blocking, deliberately deferred:

- Whether `NuGetFeedUrl` should eventually be consolidated with Cargo's
  `RegistryIndex`/npm's `NpmRegistryIndex`/PyPI's `PypiIndexUrl`/Go's
  `GoProxyUrl` into one `deps-core`-shared newtype is left for a later
  refactor once the duplication across five near-identical implementations
  is concrete, rather than speculatively generalizing now (matches this
  project's stated MVP/no-premature-abstraction principle).
- V2 (OData) protocol feed support is out of scope entirely (see Out of
  Scope) rather than an open question — `deps-nuget` implements no V2
  client today, so there is no precedent to extend.

## 10. See Also

- [[constitution]] — project principles (not yet created for this project; cross-check against `.claude/rules/*.md` instead)
- [[MOC-specs]] — all specifications
- [[023-cargo-custom-registries/spec|023-cargo-custom-registries]] — the original reference implementation pattern: `DependencySource::AlternateRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `EcosystemFormatter::can_resolve_source`, `deps_core::net_policy` host-classifier gating
- [[032-npm-npmrc-registry-support/spec|032-npm-npmrc-registry-support]] — closest file-based-config analogue: config-file parsing, per-file memoization pattern, the shared `registries.workspace_registries` policy key
- [[033-pypi-private-index-support/spec|033-pypi-private-index-support]] — closest multi-source-chain analogue: `--extra-index-url`'s additive fallback semantics, the terminal-on-transport-failure rule, and the opaque routing-key widening of `AlternateRegistry.index`'s contract, both directly reused here for NuGet's additive-source model
- [[034-go-goproxy-private-registry/spec|034-go-goproxy-private-registry]] — most recent, same-cycle-family precedent (also `specify`-only): established the `direct`-sentinel/chain-fallback pattern this spec's FR-007 mirrors, and the same auth-deferral structure this spec's Out of Scope follows
- [[027-nuget-unlisted-version-and-multiproject-lockfile/spec|027-nuget-unlisted-version-and-multiproject-lockfile]] — most recent NuGet-focused spec in this project; does not mention private feeds, confirming there is no earlier tracked artifact for the "D4"/"S4" decision this spec now documents
- `.local/testing/playbooks/competitive-parity.md` — "Private/alternative registry support" row; NuGet was not among the originally-tracked six Dependi issues and is added here as a seventh data point
- Dependi private-registry demand evidence (different repository, links intentionally not auto-linked): `` github.com/filllabs/dependi/issues/291 ``
- `crates/deps-core/src/parser.rs` — `DependencySource`, `AlternateRegistry`, `CustomRegistry`, `is_version_resolvable`
- `crates/deps-core/src/registry.rs` — `Registry` trait, `get_versions_from`/`get_latest_matching_from`
- `crates/deps-core/src/net_policy.rs` — `HostClass`, `classify_host`, `RegistryAccessPolicy`, `WorkspaceRegistryAccess`
- `crates/deps-core/src/lsp_helpers/mod.rs` — `SourcePolicy` and the other six concern-scoped `EcosystemFormatter` supertraits (split by #515)
- `crates/deps-nuget/src/ecosystem.rs:1-10` — the module-doc comment naming the "D4"/"S4" deferred-scope decision this spec is the first tracked artifact for
- `crates/deps-nuget/src/registry.rs:18` — `SERVICE_INDEX_URL`, the hardcoded constant this spec replaces with an overridable source list; also home to `ServiceIndexResponse`/`ServiceResource`, the existing two-hop resolution this spec reuses (FR-006)
- `crates/deps-nuget/src/lockfile.rs:29` — `NUGET_ORG_URL`, the second hardcoded constant this spec must also convert (FR-013)
- Issue #248 — the Cargo silent-fallback-to-public-registry bug this spec's FR-008/US-005 explicitly avoid repeating for NuGet

### Prior Art Note

This spec additionally serves, for the historical record only (not as new
scope), as the first tracked artifact for the "(D4)"/"(S4)" decision named
inline in `crates/deps-nuget/src/ecosystem.rs:1-10`'s module doc comment —
that comment's references to a "D4" scoping decision and an "S4" behavioral
contract predate this project's `specs/` tracking convention and have no
recoverable source spec. Nothing in the module doc comment itself needs to
change as a result of this spec existing; this note exists purely so a
future reader following the "(D4)" reference has somewhere to land.

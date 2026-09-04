---
aliases:
  - NuGet Feed Authentication
  - Credentialed NuGet.Config Sources
tags:
  - sdd
  - spec
  - enhancement
  - security
  - nuget
created: 2026-09-04
updated: 2026-09-04
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[035-nuget-private-feed-support/spec|NuGet Private/Custom Feed Support]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
---

# Feature: NuGet Feed Authentication (credentialed `NuGet.Config` sources)

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Issues**: [#561](https://github.com/bug-ops/deps-lsp/issues/561) (authentication),
> [#562](https://github.com/bug-ops/deps-lsp/issues/562) (origin-pinning + registration-hive
> enrichment, a **prerequisite** of #561, not a splittable follow-up — see §6)
> **Branch**: `feat/561-nuget-feed-auth`
> **Priority**: P3 (#561), P4 (#562)
> **Type**: enhancement/security — amends a shipped spec's NFR and a shared `deps-core` security
> primitive

## 1. Overview

### Problem Statement

Spec 035 (PR #560) shipped `deps-nuget` private/custom feed *resolution* — which feed a package
belongs to — but deliberately zero *authentication*: any source with an associated
`<packageSourceCredentials>` block is detected and excluded from resolution entirely (FR-009),
matching the Cargo/npm/PyPI/Go phase-1 precedent. That is correct fail-closed behavior for phase 1,
but it means Azure DevOps PAT feeds, GitHub Packages token feeds, and BaGet/ProGet instances
requiring basic auth are not reachable end-to-end today — issue #561.

Separately, spec 035 §5a and NFR-003(3) name two enrichments the public `api.nuget.org` tier already
has that a workspace-declared feed does not: origin-pinned transport (a workspace-declared feed's
`PackageBaseAddress` fetch can be redirected to any other `Global`-classified host under
`public_only`) and registration-hive enrichment (publish-time freshness, hover-only
`*(unlisted)*` marker) — issue #562.

**#562 is a prerequisite of #561, not an independent follow-up.** Sending a credential requires an
origin-pinned transport — `deps-core`'s existing `get_cached_workspace_with_headers` explicitly
documents "this method must never carry a credential" because it permits cross-origin redirects
under `public_only`. `Transport::origin_pinned` (the transport that *is* safe to carry credentials)
hardcodes `AddrGuard::Baseline` and the unnamespaced `CacheTier::Baseline` cache tier, so an
authenticated workspace-declared feed would both lose the connect-address policy guard (the #455
DNS-rebinding class) and write an authenticated response body into a cache entry an unauthenticated
`get_cached` of the same URL could read back. This spec's transport work (FR-013–FR-017) closes that
gap first; #562's registration-hive enrichment (FR-012) then falls out of the same fix nearly for
free.

This spec was produced from a three-round architect/critic design review (converged, 0 critical
findings open) rather than directly from the issues, because the design touches a shared
`deps-core` security primitive (`HttpCache`, `Transport`) and amends spec 035's NFR-001 invariant —
see §6 and §9.

### Goal

A NuGet dependency routed to an authenticated private feed — via cleartext credentials declared in
the user-profile `NuGet.Config` tier — resolves with the same hover/diagnostic/completion fidelity
a public-registry dependency gets today, including publish-time freshness and unlisted markers, with
the credential never logged, never surfaced in LSP output, never sent cross-origin, and evicted from
cache the moment the server observes it has been revoked. Repo-tier `NuGet.Config` files remain
exactly as untrusted as spec 035 made them — nothing in this spec weakens that.

### Out of Scope

> [!danger] Explicit Exclusions
> - **DPAPI-encrypted `<Password>` values** — permanently out of scope (Windows-only,
>   `CryptUnprotectData`-dependent, not portably decryptable). Rejected at parse time with a distinct
>   `EncryptedPasswordUnsupported` reason rather than silently dropped (FR-003).
> - **Repo-tier credentials, including via an opt-in setting.** Considered and rejected during design
>   (see §9): a cloned repository controls both the credential-shaped value and the destination URL,
>   so any repo-tier expansion or credential-reading is an arbitrary-secret-exfiltration primitive a
>   settings key cannot safely gate. Repo-tier `<packageSourceCredentials>` keeps spec 035's FR-009
>   fail-closed behavior verbatim and unconditionally (FR-004).
> - **`%ENV_VAR%` expansion outside `<packageSourceCredentials>` values.** `<packageSources><add
>   value>` is never expanded — an unexpanded literal there fails URL validation and fails closed
>   with zero new code, exactly as spec 035 already ships.
> - **Machine-wide config tier** (`/etc/opt/NuGet/Config`, `%ProgramFiles(x86)%\NuGet\Config`) —
>   explicit non-goal, not merely deferred.
> - **Cross-ecosystem adoption of the pinned-authenticated transport** by Cargo/npm/PyPI/Go — the
>   `deps-core` primitives this spec adds (`Transport::origin_pinned_guarded`, `CacheTier::Pinned`)
>   are usable by those ecosystems' own workspace-registry paths, but wiring them up is a dedicated
>   follow-up issue, not this PR.
> - **A `trusted_clients` pool capacity cap.** Considered during design and dropped (§6, FR-017) — if
>   ever needed, it is a `deps-core` PR covering all three current callers
>   (`deps-core::github.rs`, `deps-cargo::sparse.rs`, `deps-nuget::registry.rs`), not introduced here.
> - **`<packageSourceMapping><clear/>`** — unrelated to this spec; stays out of scope per spec 035
>   FR-018's own documented cut.

## 2. User Stories

### US-001: Credentialed private feed resolves end-to-end

AS A developer whose company's Azure DevOps/GitHub Packages/BaGet feed requires basic-auth
credentials
I WANT the LSP to authenticate using a `ClearTextPassword` credential declared in my user-profile
`NuGet.Config`
SO THAT hover/diagnostics/completion work for packages on that feed, not just detection-and-skip

**Acceptance criteria:**
```
GIVEN a user-profile NuGet.Config declaring
      <packageSources><add key="CorpFeed" value="https://pkgs.dev.azure.com/org/_packaging/x/nuget/v3/index.json" /></packageSources>
      <packageSourceCredentials><CorpFeed>
        <add key="Username" value="user" /><add key="ClearTextPassword" value="pat-value" />
      </CorpFeed></packageSourceCredentials>
  and a repo NuGet.Config declaring the same key/URL (or the settings gate on, see US-005)
WHEN I hover over a dependency resolved to CorpFeed
THEN the request carries a Basic-auth header and returns live data
```

### US-002: `%ENV_VAR%` credential expansion

AS A developer using a credential provider / CI secret injection that writes
`%CORP_FEED_PAT%` into the user-profile config rather than a literal secret
I WANT the LSP to expand the variable at resolve time
SO THAT rotating the underlying secret takes effect without editing any config file

**Acceptance criteria:**
```
GIVEN a user-profile <ClearTextPassword value="%CORP_FEED_PAT%" /> and CORP_FEED_PAT set in the
      server process environment
WHEN the feed is queried
THEN the expanded value is used for that request and never appears in InvalidEntry.raw, logs, or
     hover/diagnostic output; changing the environment variable's value takes effect on the next
     resolve without requiring a file-mtime change
```

### US-003: Credential never leaves the declared feed's origin

AS A developer relying on a private feed
I WANT the LSP to never attach my credential to a request whose target host differs from the feed I
declared it for
SO THAT a compromised or malicious service-index response cannot exfiltrate my PAT to an
attacker-controlled host

**Acceptance criteria:**
```
GIVEN CorpFeed's service index legitimately resolves PackageBaseAddress to
      https://pkgs.dev.azure.com/org/_packaging/x/nuget/v3/flat2/ (same origin, different path)
WHEN the flat-container fetch runs
THEN the credential is attached (same origin)
GIVEN a compromised service index instead resolves PackageBaseAddress to
      https://attacker.example/
THEN the credential is withheld; the request either fails the policy gate or proceeds unauthenticated
     — it is never sent to attacker.example with the PAT attached
```

### US-004: Registration-hive enrichment for alternate feeds

AS A developer using a private feed
I WANT the same publish-time freshness data and hover-only `*(unlisted)*` marker that
`api.nuget.org`-resolved packages already get
SO THAT a private-feed dependency is not a second-class citizen in hover output

**Acceptance criteria:**
```
GIVEN a package resolved via a workspace-declared or credentialed feed whose service index exposes
      RegistrationsBaseUrl
WHEN I hover over that dependency
THEN publish-time freshness and unlisted-version markers render identically to a public-registry
     dependency, subject to the existing MAX_EXTERNAL_PAGE_FETCHES cap
```

### US-005: Settings-gated user-profile sources as routing hops

AS A developer with a machine-wide `dotnet nuget add source` declaration and no repo-local
`NuGet.Config`
I WANT to opt in to routing every project on this machine through that source
SO THAT the common real-world CLI workflow (not just a repo-committed config) is supported, while
understanding this trades away OSV/deps.dev/hover-trust signals for every package on the machine

**Acceptance criteria:**
```
GIVEN registries.nuget_user_profile_sources = true and a user-profile-only <add key="CorpFeed" .../>
      with no repo NuGet.Config declaring it
WHEN I hover over a dependency
THEN it resolves via CorpFeed as an AlternateRegistry-sourced dependency (OSV/deps.dev/hover-trust
     suppressed, as already documented in spec 035 §5a)
GIVEN the setting is false (default)
THEN the same user-profile file contributes credentials only — no routing effect — and every
     project's resolution is byte-identical to a run with no user-profile file at all
```

### US-006: Credential rotation takes effect without restart

AS A developer whose PAT was rotated by a credential-provider tool
I WANT an already-open document's next hover to use the new credential
SO THAT I don't have to restart the LSP server or reopen every file after a routine rotation

**Acceptance criteria:**
```
GIVEN a document already parsed and resolved against CorpFeed with credential A
WHEN the user-profile config's ClearTextPassword changes to credential B and the document is
     reparsed (edit, save, or config-change reparse)
THEN the next hover uses credential B; no PackageNotFound regression, even if the alternates pool is
     at its registration cap (MAX_ALTERNATE_REGISTRIES)
```

### US-007: Revoked credential never serves stale private data

AS A developer whose PAT was revoked (leaked, employee offboarded, expired)
I WANT the LSP to stop serving cached data fetched under that credential the moment a 401/403 is
observed
SO THAT stale private-feed data is not shown as if it were still authoritative

**Acceptance criteria:**
```
GIVEN a cached, authenticated response body for a private-feed URL
WHEN a revalidation request against that URL returns 401 or 403
THEN the cache entry is evicted and the error is surfaced — never the default stale-while-revalidate
     fallback that serves the last-known-good body
```

## 3. Trust Model and Credential Binding Rules

This is the security-critical core of the spec. There are **two distinct comparisons** — do not
conflate them:

### 3.1 C1 — Fetch-routing origin binding (send-scope: "is this specific HTTP request allowed to
carry the credential?")

A credential already attached to a `NuGetRegistry` is included on an outbound request **iff**:

1. The request's target URL's origin equals the `NuGetRegistry`'s **declared source origin** —
   `Url::origin().ascii_serialization() + "/"` of the `NuGetFeedUrl` the registry was built from
   (trailing `/` is load-bearing: it defeats `https://pkgs.dev.azure.com.evil.test/` under a naive
   `starts_with`), **and**
2. the transport's `trusted_prefix` for this call also has that same origin.

Both sides go through one `origin_of(s) -> Option<String>` helper
(`Url::parse(s).ok().map(|u| u.origin().ascii_serialization() + "/")`) so the comparison is
normalization-immune (host case, default port, IDN) — plain `starts_with` on a feed-supplied,
un-reparsed JSON string is not sufficient. **A parse failure on either side is a mismatch — fail
closed, unauthenticated**, never an error. `declared_origin` itself cannot fail to parse (it is
derived from an already-`NuGetFeedUrl`-validated string, and that validator's https enforcement is
what rules out `Url::origin()`'s opaque `"null"` serialization).

This governs **origin, not path** — a real Azure DevOps feed legitimately serves
`PackageBaseAddress` at a different path of the same origin than `service_index_url`; path-pinning
would break every real private feed. An off-origin `@id` (FR-010's per-`@id` policy check from spec
035, or a compromised service index) stays reachable through the unauthenticated origin-pinned
workspace transport (§3.3) or the public transport — only the credential is withheld, the request is
never dropped outright by this rule alone.

### 3.2 C2 — Credential binding (bind-scope: "does this declared source even get a credential at
all?")

Both operands here are **declared source URLs** (`NuGet.Config` `<add>` values the user or a repo
wrote), never a feed-supplied `@id` — a materially different comparison from C1, which is why C1
uses origin equality and C2 uses full-URL equality:

> A credential declared under key `K` in the **user-profile** config binds to that file's own
> `<add key="K">` URL. It attaches to a resolved entry `E` **iff all of**:
>
> - **(0)** `E.key`'s key-candidates do not overlap any member of the user-profile
>   credential-suppression set (§3.4) — union match, the fail-closed direction for an *exclusion*.
> - **(1)** exactly one user-profile credential's key-candidates overlap `E.key`.
> - **(2)** exactly one `user_profile_add` entry's key-candidates overlap `K`.
> - **(3)** `E.value == user_profile_add[K].value` — **normalized full-URL equality**, not origin
>   equality. Both operands are already `Url`-normalized, https-enforced, userinfo-rejected,
>   trailing-slash-trimmed `NuGetFeedUrl`s, so plain string equality on `.as_str()` *is* the
>   normalized comparison.
>
> If any user-profile credential's key-candidates match `E` but any of (0)–(3) fails, `E` fails
> closed as `InvalidEntry(HasCredentials)` — **never** queried unauthenticated (which would leak the
> private package name) — except the FR-008 public-index carve-out (§3.5).

**Why (3) must be full-URL equality, not origin equality**: `pkgs.dev.azure.com` and
`nuget.pkg.github.com` are single hosts shared by every tenant/organization, and a corporate
Artifactory/Nexus is shared by every team. If (3) only compared origins, a hostile repository could
declare `<add key="CorpFeed" value="https://pkgs.dev.azure.com/<attacker-org>/_packaging/x/nuget/v3/index.json"/>`
and the LSP would send the user's real PAT to the attacker's own project on the same shared host — a
forced-authenticated-GET primitive reaching same-origin non-feed endpoints under the user's identity.
Full-URL equality closes this: the credential only ever attaches when the repo declares *the exact
same feed URL* the user configured, which is the legitimate case this feature exists to serve.

Condition (1)/(2) share one generic **exactly-one-match helper**
(§3.6, `unique_overlap`) with spec 035's existing `<packageSourceMapping>` key resolution — an
*inclusion* lookup where a union match (the non-transitive `key_candidates_overlap` funnel) is
fail-open, so ambiguity (zero or ≥2 matches) must fail closed rather than pick the first match.

### 3.3 Origin-pinned authenticated transport (`deps-core`)

`Transport::origin_pinned_guarded(trusted_origin, &Arc<RegistryAccessPolicy>)` pairs the existing
`trusted_origin_redirect_policy` (stops any redirect leaving the trusted origin) with
`AddrGuard::WorkspaceDeclared(snapshot)` (the connect-address policy guard, #455-class protection)
and a new `CacheTier::Pinned { digest: u64, authenticated: bool }` tier. One constructor serves both
#562's unauthenticated workspace-declared fetches and #561's authenticated ones — `authenticated`
distinguishes them for cache eviction (§3.7) without affecting pooling. The shipped
`Transport::origin_pinned` (the public `api.nuget.org` path) is **unchanged**, stays on
`CacheTier::Baseline` — zero behavior change for existing callers, cross-ecosystem or otherwise.

### 3.4 Credential-suppression set (a machine-wide-`<disabledPackageSources>` carve-out)

A user-profile `<disabledPackageSources>` entry does **not** enter the machine-wide `disabled`
routing set (§3.8 keeps that gated off entirely) — instead it accumulates into a separate
`user_profile_credential_suppressed: HashSet<String>` used only by condition (0) above. Effect: a
user who disabled `CorpFeed` in their own profile never has their PAT attached to a repo-declared
`CorpFeed`, without affecting whether any other project's `CorpFeed` entry is queried at all.

### 3.5 Public-index carve-out (FR-008)

A user-profile-derived `credentialed_keys` match against `E` does **not** force `HasCredentials` when
`is_public_registry_url(E.value)` is true (`E` resolves to the real `api.nuget.org`). This preserves
today's shipped behavior for the common Azure-Artifacts-upstreaming shape (a user-profile
`<packageSourceCredentials><nuget.org>` entry for upstream authentication) without regressing it.
**Correction to the design chain's own earlier wording**: this is *not* a claim that querying
`api.nuget.org` by package name is leak-free — it already leaks the name to Microsoft, which is
exactly the class of leak #561 exists to close elsewhere. The carve-out exists solely because
`deps-lsp` already performs this unauthenticated public-index lookup today, and this feature must
not regress an already-shipped behavior. It never attaches a credential to a public-index entry.
Users who want the public index itself treated as private should not declare it in
`<packageSources>`.

### 3.6 `unique_overlap` helper

```
fn unique_overlap<'s, T>(key: &str, items: &'s [T], key_of: impl Fn(&T) -> &str) -> Option<&'s T>
```

Used at exactly three inclusion sites: spec 035's `<packageSourceMapping>` key resolution
(`resolve_mapping_source_key`), C2 condition (1) (credential → entry), and C2 condition (2)
(credential key → user-profile `<add>`). All other `key_candidates_overlap` uses in this codebase
are **exclusion** lookups (`file.removed`'s `retain`, `disabled_keys`/`credentialed_keys` membership,
the §3.4 suppression set) and correctly stay plain union matches — union is the fail-closed direction
for an exclusion, exactly-one is the fail-closed direction for an inclusion.

### 3.7 Revoked-credential eviction (FR-015)

On the authenticated tier (`CacheTier::Pinned { authenticated: true, .. }`) only, a 401/403 response
to a revalidation request evicts the cache entry (with the `total_bytes` accounting fix-up) instead
of the default stale-while-revalidate fallback (`get_cached_with_headers_via`'s `Err` arm), which
would otherwise serve a possibly-revoked-credential's last-known-good body indefinitely. Every other
tier's stale-while-revalidate behavior is unchanged.

### 3.8 Settings-gated routing (the M3 gate, FR-006)

`registries.nuget_user_profile_sources` (new `bool`, `RegistriesConfig`, default `false`,
backward-compatible — the section is not under `deny_unknown_fields`) splits `resolve`'s
per-ancestor-file accumulation loop into two halves for a `UserProfile`-tier file:

- **Credential half — always runs, regardless of the flag**: `credentialed_keys`,
  `user_profile_credential_suppressed` (§3.4), `credentials` (expanded per FR-002), and
  `user_profile_add` (built from that file's own `<clear/>`/`<add>`/`<remove>` batch — required
  because C2 condition (3) needs somewhere to read from in *either* flag mode).
- **Routing half — skipped entirely when the flag is false**: `sources`, `sources_cleared`,
  `removed` (including `nuget_org_removed`), `disabled`, `mapping` — **all six** routing
  contributions, not just `sources` alone. Gating only `sources` while leaving
  `sources_cleared`/`mapping` ungated would let a user-profile `<clear/>` or
  `<packageSourceMapping>` fail every `.NET` project on the machine closed — strictly worse than the
  `AlternateRegistry`-downgrade tradeoff the flag exists to make opt-in.

With the flag off (default), #561 delivers credentials for **repo-declared** sources whose URL
matches the user's own `<add>` (C2), and #562 ships unconditionally. With the flag on, user-profile
sources additionally become routing hops, with the already-documented (spec 035 §5a)
OSV/deps.dev/hover-trust tradeoff. Both modes share the same four-site `fetch` routing (§3.9) and the
same `CacheTier::Pinned` namespace — the flag adds one branch in `resolve`, not a second code path.

Flipping the flag off does **not** retroactively purge already-registered `alternates` chains or
force a re-parse — documented as a known limitation (takes effect on next reparse), the same
non-purge shape `set_registry_policy` already has for cached bodies.

### 3.9 Four transport-selection sites (FR-011)

| Site | `trusted_prefix` |
|---|---|
| `service_index()` | the declared source origin (no resource resolved yet) |
| `get_versions_typed_with` (flat container) | the resolved `PackageBaseAddress`-derived prefix (unchanged from spec 035) |
| `registration_enrichment_from_index` | the caller's registration prefix, plus the existing `page.id.starts_with` pre-check |
| `search_typed` | the `SearchQueryService`'s **origin**, not a `{base}/` string prefix — `search_url` appends a query string to `base`, so `{base}/` is not a prefix of the request URL |

All four route through one `NuGetRegistry::fetch(url, trusted_prefix)`, which applies C1 to decide
whether to attach the credential, then dispatches to: (1) the authenticated origin-pinned transport
when C1 holds; (2) the unauthenticated origin-pinned workspace transport when the registry's tier is
`WorkspaceDeclared`; (3) today's public `get_cached_trusted_origin` path otherwise, byte-identical to
spec 035.

## 4. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL locate a user-profile-tier `NuGet.Config` exactly once, at parse-context construction (not per manifest parse), as the first-existing of: Windows `%APPDATA%\NuGet\NuGet.Config`; Unix `$XDG_CONFIG_HOME/NuGet/NuGet.Config` (if set) → `~/.config/NuGet/NuGet.Config` → `~/.nuget/NuGet/NuGet.Config` — exactly one file, never merged. THE SYSTEM SHALL de-duplicate against the repo-tier ancestor walk (spec 035 FR-001) by canonicalized path; a path reachable at both tiers is treated as `Repo` (lower trust wins); a `canonicalize` failure on the user-tier candidate drops that candidate (fail closed) | must |
| FR-002 | THE SYSTEM SHALL parse `<packageSourceCredentials>` `Username`/`ClearTextPassword` child values into a `RedactedSecret` newtype (hand-written redacting `Debug`/`Display`) holding the **pre-expansion** literal, and SHALL expand `%ENV_VAR%` references in these values only, post-cache (in `resolve`, never in the memoized raw-file parse) — an unset variable yields `InvalidEntry(HasCredentials)`, fail closed, with `InvalidEntry.raw` retaining the unexpanded literal | must — security-relevant |
| FR-003 | THE SYSTEM SHALL reject a DPAPI-encrypted `<Password>` value at parse time with a distinct `NuGetFeedUrlError::EncryptedPasswordUnsupported` reason (never attempting decryption), logged via `tracing::debug!` naming the cause | must |
| FR-004 | Repo-tier `<packageSourceCredentials>` SHALL continue to force `HasCredentials` unconditionally, independent of any C2 binding outcome, matching spec 035 FR-009 verbatim | must — security-blocking |
| FR-005 | THE SYSTEM SHALL split a `UserProfile`-tier file's contribution to `resolve`'s accumulation loop into a credential half (always applied: `credentialed_keys`, the §3.4 suppression set, expanded `credentials`, `user_profile_add`) and a routing half (`sources`, `sources_cleared`, `removed`/`nuget_org_removed`, `disabled`, `mapping` — all six, together) | must — security-relevant |
| FR-006 | THE SYSTEM SHALL read `registries.nuget_user_profile_sources` (new `bool`, `RegistriesConfig`, default `false`) via a live `Arc<AtomicBool>` handle updated at both `initialize` and `didChangeConfiguration`, bundled with the existing `policy: Arc<RegistryAccessPolicy>` into one `EcosystemRuntime` struct passed to `register_ecosystems` (replacing what would otherwise be a 4th positional parameter). WHEN false THE SYSTEM SHALL apply FR-005's routing half from no `UserProfile`-tier file to any project — every project's `valid_hops`/`resolve_source_for` output SHALL be byte-identical to omitting that file's routing half entirely | must |
| FR-007 | THE SYSTEM SHALL attach a user-profile credential declared under key `K` to a resolved entry `E` iff all of conditions (0)–(3) in §3.2 hold; any credential-key match on `E` failing any condition SHALL fail closed as `InvalidEntry(HasCredentials)`, except the FR-008 carve-out | must — security-blocking |
| FR-008 | A user-profile-derived `credentialed_keys` match against `E` SHALL NOT force `HasCredentials` when `is_public_registry_url(E.value)` is true, and SHALL NOT attach a credential to such an entry either (§3.5) | must |
| FR-009 | Conditions (1) and (2) of §3.2, and spec 035's existing `<packageSourceMapping>` key resolution, SHALL share one generic `unique_overlap` helper (§3.6); every other `key_candidates_overlap` use (exclusion lookups) SHALL remain plain union matching | must |
| FR-010 | A credential already attached to a `NuGetRegistry` SHALL be included on an outbound request only when the C1 origin-binding rule (§3.1) holds for that specific request; a parse failure on either side of the comparison SHALL be treated as a mismatch (unauthenticated), never an error; an off-origin target SHALL remain reachable unauthenticated rather than being dropped | must — security-blocking |
| FR-011 | THE SYSTEM SHALL route every NuGet HTTP fetch for a `WorkspaceDeclared`-tier or credentialed source through exactly one `NuGetRegistry::fetch(url, trusted_prefix)`, covering the four sites in §3.9, with no other call site selecting a transport directly | must |
| FR-012 | THE SYSTEM SHALL delete the `tier == WorkspaceDeclared` early return in the registration-hive fetch path (`get_versions_typed_with`) and in `unlisted_versions_for_hover`, routing both through FR-011's `fetch`, subject to the existing `MAX_EXTERNAL_PAGE_FETCHES` cap and the existing per-`@id` policy validation (spec 035 FR-010) degrading a rejected `RegistrationsBaseUrl` to absent | must |
| FR-013 | THE SYSTEM SHALL add `Transport::origin_pinned_guarded(trusted_origin, &Arc<RegistryAccessPolicy>)` (§3.3) and a new `CacheTier::Pinned { digest: u64, authenticated: bool }` variant, where `digest = hash(trusted_origin, policy_snapshot)` — **never** including credential identity — and `HttpCache::get_cached_pinned{,_with_headers}` as the only sanctioned way to send a credential to a workspace-declared host. The shipped `Transport::origin_pinned` (public path) SHALL remain unchanged on `CacheTier::Baseline` | must |
| FR-014 | THE SYSTEM SHALL accept a separate `auth_id: Option<u64>` (a salted hash of the credential header value, per-process `OnceLock` salt) on `get_cached_pinned{,_with_headers}`, folded into `cache_key` only (never into `CacheTier` / the `trusted_clients` pool key), so a rotated or distinct credential never reads back a body fetched under a different one | must — security-relevant |
| FR-015 | On an authenticated (`CacheTier::Pinned { authenticated: true, .. }`) cache entry, a 401/403 revalidation response SHALL evict the entry (with the `total_bytes` fix-up) and return the error, instead of the default stale-while-revalidate fallback | must — security-relevant |
| FR-016 | `NuGetSourceChain.hops` SHALL be `Vec<ResolvedHop { url: NuGetFeedUrl, slot: Option<String>, auth: Option<NuGetAuth> }>` so `resolve_source_for` and `resolved_chains` — both of which reach `chain()` exclusively through `valid_hops()` — necessarily agree on hop credential data; `NuGetSourceChain::chain`'s hash SHALL cover each hop's `url` and `slot`, **never** `auth`. WHEN a credential rotates for an already-registered chain THE SYSTEM SHALL replace the `alternates` entry in place (occupied-slot, differing `auth_digest`) rather than register a new entry or evict via LRU; this replace arm SHALL NOT be gated by `MAX_ALTERNATE_REGISTRIES`'s at-capacity check, which governs only the Vacant-insertion arm | must |
| FR-017 | `trusted_clients` SHALL be re-keyed to `(String, CacheTier)` (both `Hash`) with no new capacity cap; the existing unbounded pool shared with `deps-core::github.rs` and `deps-cargo::sparse.rs` stays as-is | must |

## 5. Non-Functional Requirements (amendments to spec 035)

| ID | Category | Amendment |
|----|----------|-----------|
| NFR-001 (amended) | Security | **Was**: "no field can hold a credential" (structurally provable absence). **Now**: exactly two types may hold a credential-shaped value — `RedactedSecret` (pre-expansion literal) and `NuGetAuth` (pre-formatted `Basic` header value) — both with hand-written redacting `Debug`/`Display`, and exactly one site (`resolve`'s final pass) ever reads a value out of them into an attached credential, gated on `ConfigTier::UserProfile`. This is a read-side invariant (mirroring `deps_cargo::config::Provenance`'s shape), weaker than phase 1's structural impossibility. The structural test is rewritten to assert redaction (a `Debug`/`Display` snapshot never contains the literal secret) and the tier gate, not the absence of any credential-capable field |
| NFR-003 (amended) | Security | Spec 035 §5a / NFR-003(3) named "origin-pinning loss for alternate feeds" as an **accepted residual risk** pending a policy-tiered, purge-on-policy-change `trusted_clients` pool. That pool now exists (`CacheTier::Pinned`, FR-013/FR-017) — NFR-003(3) is **closed by #562**. Registration-hive enrichment for alternate feeds, previously skipped entirely (spec 035 §5a), is likewise **closed by #562** (FR-012) |
| NFR-004 (new) | Security | A revoked credential SHALL NOT be servable from cache after the server observes a 401/403 on it (FR-015) |
| NFR-005 (new) | Reliability | Zero behavior change for any project with `registries.nuget_user_profile_sources` left at its default (`false`) and no user-profile `<packageSourceCredentials>` binding via C2 — verified by the existing `deps-nuget` test suite producing unchanged results, plus new tests asserting flag-off routing parity (§3.8) |
| NFR-006 (new) | Maintainability | Conditions (0)–(3) of §3.2, the C1 origin-binding rule, the four-site routing table, the replace-in-place rotation rule, and the 401/403 eviction rule are each verified by a dedicated, named test (§8) |

## 6. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `ConfigTier` | New `deps-nuget` enum — which tier a parsed file came from | `UserProfile` \| `Repo`; mirrors `deps_cargo::config::Provenance`'s "nothing branches on this to *widen* trust" invariant |
| `NuGetAuth` | New `deps-nuget` newtype — pre-formatted `Basic base64(user:pass)` header value | Hand-written redacting `Debug`/`Display`; `pub(crate)` constructor; never stores user/pass separately; does **not** derive `Hash` (making "credential value in a hash key" a compile error) |
| `RedactedSecret` | New `deps-nuget` newtype — pre-expansion credential literal | Hand-written redacting `Debug`/`Display`; holds the raw `Username`/`ClearTextPassword` text before `%ENV_VAR%` expansion |
| `PackageSourceEntry` (extended) | Existing spec-035 type | `+ tier: ConfigTier` (which tier last set `value`; retained for §3.8's gate and `debug!` output, **not** the credential gate — see C2), `+ auth: Option<NuGetAuth>` (written only by `resolve`'s final pass, whole-struct assignment on every update so a new field cannot be silently missed) |
| `ResolvedHop` | New `deps-nuget` `pub` type — replaces `NuGetSourceChain.hops: Vec<NuGetFeedUrl>` | `url: NuGetFeedUrl`, `slot: Option<String>` (lowercased declared `<add key>` that supplied `auth`, `None` when unauthenticated), `auth: Option<NuGetAuth>` (never hashed, never fully `Debug`-printed) |
| `NuGetSourceChain` (extended) | Existing spec-035 type | `hops: Vec<ResolvedHop>` (was `Vec<NuGetFeedUrl>`); `key` hash covers `url`+`slot` per hop, never `auth` |
| `CacheTier::Pinned` | New `deps-core` variant | `{ digest: u64, authenticated: bool }`; `digest = hash(trusted_origin, policy_snapshot)`, no credential identity; derives `Hash` (new, alongside `WorkspaceRegistryAccess`) |
| `Transport::origin_pinned_guarded` | New `deps-core` constructor | `(trusted_origin, &Arc<RegistryAccessPolicy>) -> Transport`; pairs `trusted_origin_redirect_policy` + `AddrGuard::WorkspaceDeclared(snapshot)` + `CacheTier::Pinned` |
| `HttpCache::get_cached_pinned{,_with_headers}` | New `deps-core` methods | The only sanctioned way to send a credential to a workspace-declared host; take `auth_id: Option<u64>` folded into `cache_key` only |
| `EcosystemRuntime` | New `deps-lsp` struct, replaces a would-be 4th `register_ecosystems` parameter | `{ policy: Arc<RegistryAccessPolicy>, nuget_user_profile_sources: Arc<AtomicBool> }` — absorbs future live flags without growing arity again |
| `NuGetRegistry` (extended) | Existing spec-035 type | `+ auth: Option<NuGetAuth>`, `+ declared_origin: String` (computed once in `with_base` from the hop's `NuGetFeedUrl`), `+ auth_digest: u64` (salted hash of ordered hop `auth` values, `0` when none); `with_base` now takes `&ResolvedHop`, not a bare URL |
| `trusted_clients` (extended) | Existing `deps-core` `DashMap` | Re-keyed `String` → `(String, CacheTier)`; no capacity cap (dropped from an earlier design iteration — see §9) |
| `user_profile_add` / `user_profile_credential_suppressed` | New `resolve`-local accumulators | Built from a `UserProfile`-tier file's own `<clear/>`/`<add>`/`<remove>` batch and `<disabledPackageSources>` respectively — populated identically regardless of the FR-006 flag |

## 7. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| No user-profile `NuGet.Config` exists | Byte-identical to spec 035 behavior; `user_profile_add`/credentials empty (FR-001) |
| User-profile file declares `<ClearTextPassword value="%UNSET_VAR%"/>` | `InvalidEntry(HasCredentials)`, fail closed; unexpanded literal retained in `raw` (FR-002) |
| User-profile file declares an encrypted `<Password>` | `EncryptedPasswordUnsupported`, distinct from `HasCredentials`, `debug!`-logged (FR-003) |
| Repo file declares `<packageSourceCredentials>` for a source the user-profile also credentials with a matching URL | Repo entry still fails closed as `HasCredentials` (FR-004) — the repo tier's own credential block always wins over any C2 binding |
| Repo `<add key="CorpFeed" value="https://correct.example/...">` matches the user's own `<add key="CorpFeed">` at the same URL | Credential attaches (C2 all four conditions hold) |
| Repo `<add key="CorpFeed" value="https://pkgs.dev.azure.com/attacker-org/...">`, user's `CorpFeed` is `https://pkgs.dev.azure.com/real-org/...` (same origin, different path) | Condition (3) fails (URLs differ) → `HasCredentials`, fail closed — never sent unauthenticated either |
| CorpFeed's own service index legitimately resolves `PackageBaseAddress` to a different path on the same origin | C1 holds (same origin) → credential attached to that request |
| CorpFeed's service index resolves `PackageBaseAddress` to a different host entirely (compromised or misconfigured) | C1 fails → request proceeds unauthenticated via the workspace/public transport, or is rejected by spec 035 FR-010's policy check, never sent with the credential |
| User disabled `CorpFeed` in their own profile (`<disabledPackageSources>`), a repo declares the same `CorpFeed` at the matching URL | Condition (0) fails → `HasCredentials`; the repo's `CorpFeed` is not machine-wide disabled, only the credential is withheld |
| `registries.nuget_user_profile_sources = false`, user-profile file has `<clear/>` and no matching repo declaration | Zero routing effect from the user-profile file; project resolves exactly as if that file didn't exist (FR-005/FR-006) |
| `registries.nuget_user_profile_sources = true`, user-profile-only `<add>` with no repo `NuGet.Config` | Resolves as `AlternateRegistry` (OSV/deps.dev/hover-trust suppressed, per spec 035 §5a) |
| Credential rotates for an already-registered chain, `alternates` at `MAX_ALTERNATE_REGISTRIES` | Replace-in-place succeeds (not gated by the at-capacity check); next hover uses the new credential (FR-016) |
| A cached authenticated body's revalidation returns 401/403 | Entry evicted, error returned — no stale body served (FR-015) |
| `is_public_registry_url(E.value)` is true and a user-profile `credentialed_keys` entry matches `E.key` | No `HasCredentials` forced, no credential attached — public index queried unauthenticated exactly as spec 035 ships today (FR-008) |
| Alternate feed's `RegistrationsBaseUrl` resolves and passes spec 035 FR-010's policy check | Registration-hive enrichment (publish-time, unlisted marker) now populates, routed through `fetch` (FR-012) |

## 8. Success Criteria / Acceptance Tests

| ID | Test | Verifies |
|----|------|----------|
| SC-001 | Live or mocked Azure-DevOps/BaGet-shaped fixture with a `ClearTextPassword` credential returns authenticated hover/completion data | US-001, FR-002, FR-010 |
| SC-002 | `%ENV_VAR%` expansion test: set/unset the process env var, assert `InvalidEntry` fail-closed on unset, live data on set, and that `RedactedSecret`/`NuGetAuth` `Debug` output never contains the literal | US-002, FR-002, NFR-001 |
| SC-003 | Origin-binding test: mock a service index returning an off-origin `PackageBaseAddress`; assert the fetch either fails policy or proceeds without the `Authorization` header | US-003, FR-010 |
| SC-004 | Registration-hive enrichment test on an alternate-feed fixture: publish-time and unlisted marker present in hover output | US-004, FR-012 |
| SC-005 | Settings-gate parity test: with the flag off, a user-profile file with `<clear/>`/`<packageSourceMapping>`/`<disabledPackageSources>` produces byte-identical `valid_hops` to a run with no user-profile file | US-005, FR-005, FR-006, NFR-005 |
| SC-006 | C2 full-URL-equality test: same-origin-different-path repo entry fails closed; exact-URL-match repo entry succeeds | §3.2, FR-007 |
| SC-007 | Credential-suppression test (§3.4): a repo-declared source matching a user-profile-disabled key fails closed (`HasCredentials`) rather than being queried unauthenticated — suppression withholds the credential, it never downgrades the source to an anonymous request | §3.4, FR-007 condition (0) |
| SC-008 | Rotation test: fill `alternates` to `MAX_ALTERNATE_REGISTRIES`, rotate a credential on an already-registered chain, assert the head client carries the new credential and the replace arm is not blocked by the cap | US-006, FR-016 |
| SC-009 | Revocation test: mock a 401 on revalidation of a cached authenticated entry, assert eviction (not stale-while-revalidate) | US-007, FR-015 |
| SC-010 | Repo-tier invariant test: a repo `<packageSourceCredentials>` entry fails closed as `HasCredentials` regardless of any user-profile C2 match | FR-004 |
| SC-011 | Four-site routing test: mock 401 on `index.json` itself (service index) and on `SearchQueryService`, assert both are covered by the authenticated `fetch` path, not just the flat-container/registration sites | §3.9, FR-011 |
| SC-012 | Public-index carve-out test: a user-profile credential named for `nuget.org` never attaches to, nor blocks, a repo entry resolving to the real public index | FR-008 |

## 9. Open Questions

All `[NEEDS CLARIFICATION]` items from the design chain were resolved before this spec was written —
the architect/critic review converged after three rounds with zero critical findings open. Nothing
below blocks implementation; these are the deliberately-deferred items surfaced during design.

- **Repo-tier credentials via an opt-in setting** — considered (architect round 1) and rejected: a
  settings key cannot distinguish a legitimate CI-generated/gitignored local config from a hostile
  checked-in one, and the value delivered is smaller than the user-profile shape. Left for a future
  issue if real demand appears, with its own threat-model writeup.
- **`trusted_clients` capacity cap** — considered (critic round 2/3) and dropped: the credential-count
  growth vector that originally motivated a cap was removed by keeping `auth_id` out of the pool key
  (FR-014/FR-017), and the pool is shared by two other ecosystems' clients, so a first-ever cap
  belongs in its own `deps-core` PR if the pool's actual (config-count-bounded, not credential-bounded)
  size is ever a real problem.
- **Cross-ecosystem adoption of `Transport::origin_pinned_guarded`/`CacheTier::Pinned`** — explicitly
  out of scope for this PR (§Out of Scope); a natural follow-up once Cargo/npm/PyPI/Go's own
  workspace-registry paths want the same origin-pinning-plus-policy-guard combination.
- **Machine-wide config tier** — non-goal, matching spec 035's identical cut for the repo-tier
  ancestor walk.

## 10. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D
  warnings`, `cargo nextest run --workspace --all-features` before considering a task complete.
- Follow the Registry Integration Gate (`.claude/rules/continuous-improvement.md`) — verify against a
  real or mocked credentialed private NuGet V3 feed before filing the implementation PR.
- Update `CHANGELOG.md`, `ECOSYSTEM_GUIDE.md` (document the flag, its default, the enrichment
  tradeoff, and the M5/FR-008 carve-out's corrected rationale — see §3.5), `specs/035-nuget-private-feed-support/spec.md`
  (NFR-001/NFR-003 amendments per §5), `.local/testing/coverage.md`, `.local/testing/playbooks/nuget.md`,
  `.local/testing/regressions.md`.
- Route every fetch that can occur for a `WorkspaceDeclared`-tier or credentialed source through the
  single `NuGetRegistry::fetch` (FR-011) — no ad hoc transport selection at a new call site.

### Ask First
- Any change to `Transport::origin_pinned` (the shipped public-tier constructor) — it must remain
  byte-identical; this spec only adds `origin_pinned_guarded` alongside it.
- Consolidating `NuGetAuth`/`RedactedSecret` with any Cargo/npm/PyPI/Go credential-shaped type — a
  cross-crate refactor beyond this spec's file scope, same posture as spec 035's `NuGetFeedUrl` note.
- Reintroducing a `trusted_clients` capacity cap — belongs in its own `deps-core` PR per §9.

### Never
- Attach a credential to a request that fails the C1 origin-binding rule (§3.1) or bind one to an
  entry that fails any of C2's conditions (0)–(3) (§3.2), except the FR-008 public-index carve-out.
- Expand `%ENV_VAR%` outside `<packageSourceCredentials>` values, or before the `NuGetConfigCache`
  memo boundary (FR-002).
- Let repo-tier `<packageSourceCredentials>` bypass its unconditional fail-closed behavior (FR-004).
- Include credential identity in `CacheTier`, the `trusted_clients` pool key, or
  `NuGetSourceChain::chain`'s hash (FR-013/FR-016/FR-017) — credential identity belongs only in
  `cache_key` via the separate `auth_id` argument.
- Log, `Debug`-print in full, or surface in hover/diagnostic output any value held by `RedactedSecret`
  or `NuGetAuth` (NFR-001).

## 11. See Also

- [[035-nuget-private-feed-support/spec|035-nuget-private-feed-support]] — the spec this work amends
  (NFR-001, NFR-003, §5a); establishes `NuGetConfig`, `PackageSourceEntry`, `NuGetSourceChain`,
  `NuGetRegistry`, the root-to-leaf repo-tier merge, and the `<packageSourceMapping>`
  `unique_overlap`-shaped key resolution this spec reuses
- [[023-cargo-custom-registries/spec|023-cargo-custom-registries]] — `deps_cargo::config::AuthToken`/
  `Provenance`/`IndexTrust` and `sparse.rs::fetch`'s origin-pinned-with-headers pattern, the direct
  reuse target for this spec's credential trust model and transport
- [[MOC-specs]] — all specifications
- Issue [#561](https://github.com/bug-ops/deps-lsp/issues/561) — authentication for credentialed
  private feeds
- Issue [#562](https://github.com/bug-ops/deps-lsp/issues/562) — origin-pinning and registration-hive
  enrichment for alternate feeds (this spec's prerequisite work, §Overview)
- `crates/deps-core/src/cache.rs` — `HttpCache`, `Transport`, `CacheTier`, `trusted_clients`
- `crates/deps-core/src/net_policy.rs` — `WorkspaceRegistryAccess`, `RegistryAccessPolicy`
- `crates/deps-nuget/src/config.rs` — `NuGetConfig`, `PackageSourceEntry`, `resolve`,
  `key_candidates_overlap`, `resolve_mapping_source_key`
- `crates/deps-nuget/src/registry.rs` — `NuGetRegistry`, `with_base`, `register_chain`,
  `service_index`, `get_versions_typed_with`, `registration_enrichment_from_index`, `search_typed`
- `crates/deps-lsp/src/config.rs` — `RegistriesConfig`
- `crates/deps-lsp/src/{lib.rs,server.rs,document/state.rs}` — `EcosystemRuntime`,
  `register_ecosystems`, the `initialize`/`didChangeConfiguration` flag-update sites

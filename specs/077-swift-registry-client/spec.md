---
aliases:
  - Swift Package Registry Client
  - SE-0292 Registry Support
tags:
  - sdd
  - spec
  - enhancement
  - security
  - swift
created: 2026-10-06
updated: 2026-10-06
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[043-nuget-feed-authentication/spec|NuGet Feed Authentication]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
  - "[[032-npm-npmrc-registry-support/spec|npm .npmrc Registry Support]]"
---

# Feature: Swift Package Registry (SE-0292) client for `.package(id:)` dependencies

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Issues**: [#1691](https://github.com/bug-ops/deps-lsp/issues/1691)
> **Branch**: `feat/1691-swift-registry-client`
> **Priority**: P4
> **Type**: enhancement/security. Adds a credential-carrying registry client plus small, additive
> `deps-core` primitives: a shared `Basic` header helper, `Link` capture on `HttpCache` responses,
> a `rel="next"` detector, and one `DepsError` variant

## 1. Overview

### Problem Statement

PR for #1679 parses `.package(id: "scope.name", ...)` (SE-0292 registry identity) but never resolves
it: the dependency is `DependencySource::CustomRegistry { url: <scope as written> }`, shown and never
queried. SwiftPM has no public default registry, so resolving one requires the scope-to-registry
mapping in `registries.json`, an SE-0292 HTTP client, and (for every real private registry)
credentials. `Package.resolved` registry pins are mis-mapped to `ResolvedSource::Git`, and the stored
scope keeps its original case although SwiftPM identities are case-insensitive.

This spec is the output of two architect/critic rounds (both critic verdicts `significant`, all
findings resolved here). It records three deliberate deviations from SwiftPM (§3.6) and the decisions behind
credential binding, policy exemption, and truncation handling.

### Goal

An `id:` dependency whose scope maps to a configured registry resolves with the same hover,
inlay, diagnostic and lockfile fidelity as a GitHub-backed `url:` dependency, against the registry
the user configured. Credentials from the environment reach only registry URLs the user configured
in their own user-level `registries.json`. A hostile repository cannot redirect a credential, cannot
change how it is formatted, and cannot use a broken or unreadable config to make private scope names
reach any registry other than the one SwiftPM would use.

### Out of Scope

> [!danger] Explicit Exclusions
> - **Following `Link: rel="next"` pages.** Shipped in the #1754 follow-up (FR-034, FR-035).
> - **An actionable error for connect-time policy blocks** (`DepsError::HostBlockedByPolicy`).
>   Shipped in the #1758 follow-up (FR-036).
> - **Path-suffix watched-config matching** (watch `.swiftpm/configuration/registries.json` and
>   nothing else). This is a general watcher change touching `deps-core` `EcosystemRegistry` and
>   `deps-lsp` `server.rs`, so it is a separate follow-up. In the meantime Swift watches the
>   basename `registries.json` (FR-041); the only cost is an extra reparse when an unrelated file
>   with that name changes.
> - **macOS Keychain credentials.** Shipped as the opt-in `registries.swift_keychain_credentials`
>   setting (#1771, FR-044). `~/.netrc` and `SWIFTPM_NETRC_DATA` shipped in the #1755 follow-up
>   (FR-038).
> - **`publishedAt` freshness.** Shipped in the #1756 follow-up (FR-037).
> - **SCM-to-registry swizzling** (`--use-registry-identity-for-scm`, `--replace-scm-with-registry`),
>   #1757.
> - **Marking the registry `Authorization` header sensitive** (`HeaderValue::set_sensitive`).
>   Shipped cross-ecosystem in #1772 through `deps_core::RequestHeader`.
> - **Name completion for `id:` literals.** SE-0292 has no search endpoint.
> - **Centralizing the credential-provenance predicate (#1459).** Shaped for reuse here (FR-016),
>   extracted later.

## 2. User Stories

### US-001: Private registry dependency resolves end-to-end
AS A developer whose user-level `registries.json` maps scope `acme` to a private registry, with
`SWIFTPM_REGISTRY_TOKEN` exported
I WANT `.package(id: "acme.Networking", from: "2.0.0")` to show latest/outdated/unsatisfiable data
SO THAT registry dependencies are not second-class next to `url:` dependencies.
```
GIVEN user tier {"registries":{"acme":{"url":"https://swift.acme.dev/api"}},"version":1}
  AND SWIFTPM_REGISTRY_TOKEN=t
WHEN I hover the dependency
THEN GET https://swift.acme.dev/api/acme/networking is sent with Accept
     application/vnd.swift.registry.v1+json and Authorization: Bearer t
 AND the hover lists the registry's releases
```

### US-002: Project-committed registry config works without leaking credentials
AS A developer opening a repository that commits `.swiftpm/configuration/registries.json`
I WANT its registry dependencies resolved
SO THAT a team-shared config needs no per-user setup, while my token only goes where I sent it.
```
GIVEN project tier [default] = https://artifactory.corp/api/swift/team-a
  AND user tier lists exactly that URL
THEN requests carry my credential
GIVEN project tier [default] = https://artifactory.corp/api/swift/attacker-repo
  AND user tier lists only https://artifactory.corp/api/swift/team-a
THEN requests to attacker-repo are sent unauthenticated through the policy-guarded transport
```

### US-003: Intranet registry from my own config is reachable under the default policy
```
GIVEN user tier registry https://swift.intra.corp (resolves to 10.0.0.5)
  AND registries.workspace_registries = public_only (default)
THEN the registry is queried (user-tier URLs are exempt, as Cargo's $CARGO_HOME tier is)
GIVEN the same hostname declared only in the project tier
THEN the pinned transport refuses the connection and the dependency shows the generic fetch failure
     (an actionable message is a follow-up, see Out of Scope)
GIVEN the project tier declares the IP literal https://10.0.0.5
THEN a blocked_registries diagnostic is emitted at parse time and no request is made
```

### US-004: Paginated registry never produces false data
```
GIVEN a registry whose first page sends Link: <...?page=2>; rel="next"
THEN the pages are followed and merged into one release list (FR-034)
 AND WHEN the pages cannot be followed to the last one, the dependency shows an actionable fetch
     failure ("registry returned an unusable next-page link", "registry release list exceeds the
     page limit" or "registry release list took too long to fetch"), and no latest version, no
     "up to date" mark and no unsatisfiable or outdated diagnostic is derived from a partial list
```

## 3. Trust Model

### 3.1 Configuration tiers (verified against SwiftPM `release/6.4.0`)

| Tier | Path | Selection |
|------|------|-----------|
| Project | `<dir of Package.swift>/.swiftpm/configuration/registries.json` | no ancestor walk |
| User (macOS) | `~/Library/org.swift.swiftpm/configuration/registries.json` | always, exactly this one path |
| User (other) | `$XDG_CONFIG_HOME/swiftpm/configuration/registries.json` if `XDG_CONFIG_HOME` is set, else `~/.swiftpm/configuration/registries.json` | exactly one path, never an existence fallback |

On Linux, swift-foundation's `_XDGSearchPathURL` returns `nil` for `.libraryDirectory`, so SwiftPM
falls back to `dotSwiftPM`. Merge follows `RegistryConfiguration.merge` and `registry(for:)`: project
overrides user per scope key and for `[default]`. Lookup is `scoped[scope] ?? default` after the merge,
so a user-tier scoped entry wins over a project-tier `[default]`.

### 3.2 Registry trust is a function of the URL alone

Let `U` be the set of normalized URLs of every valid user-tier registry entry, scoped and
`[default]`. `authentication`-only host keys are not part of `U`. A resolved registry URL `R` is:

- `Trusted` iff `R ∈ U`, whichever tier declared it in the current workspace;
- `WorkspaceDeclared` otherwise.

Normalization goes through `url::Url`: lowercase host, IDN converted to punycode, default port
dropped, trailing `/` trimmed, path kept case-sensitive. Equality is string equality of that form.
Trust depends only on `(R, U)`, and `U` is process-global, so trust, transport and credential
binding never differ between two workspaces sharing `R`. That is what prevents the shared client
from flapping between configurations (critic S2).

### 3.3 Credential binding (spec 043 §3.2 rule, adapted)

An environment credential attaches to requests for registry `R` **iff** `R` is `Trusted`. In
other words, `R` was declared in the user tier or equals a user-tier URL exactly (full normalized
URL, never host or origin). Path-tenanted shared hosts (Artifactory `/api/swift/<repo>`, SaaS
`host/<org>/<repo>`) are exactly what host-level binding would expose. A hostile project entry
pointing at another tenant on a trusted host receives no credential.

> [!warning] One credential, every user-tier registry
> The environment holds a single credential, not one per registry. It is attached to **every**
> `Trusted` registry. That includes a public `[default]` (e.g. `https://tuist.dev/api/registry/swift`)
> listed in the user tier next to a private scoped registry. SwiftPM `main` does the same thing,
> since its origin binding (§3.6) also covers every configured registry. A user who does not want
> the token sent to a public registry must not list that registry in the user tier while
> `SWIFTPM_REGISTRY_TOKEN` is exported. The mdBook states this.

### 3.4 Credential formatting

The auth type comes **only** from the user tier's `authentication` map, keyed by
`RegistryHostKey(R)` (§6). A project file cannot change it. Formatting mirrors SwiftPM
`RegistryClient` (`user == "token"` heuristic included):

| Env credential | User-tier type | Header |
|----------------|----------------|--------|
| `Token(t)` | none or `token` | `Bearer t` |
| `Token(t)` | `basic` | `Basic b64("token:" + t)` |
| `Login(u, p)` with `u == "token"` | none | `Bearer p` |
| `Login(u, p)` | none (u != "token") or `basic` | `Basic b64(u:p)` |
| `Login(u, p)` | `token` | `Bearer p` |

Env precedence: a non-empty `SWIFTPM_REGISTRY_TOKEN` wins. Otherwise a non-empty
`SWIFTPM_REGISTRY_LOGIN` with a non-empty `SWIFTPM_REGISTRY_PASSWORD` is used. Either one alone means
no credential, plus a warning that names only the variable.

### 3.5 Network policy and transport

| Trust | Parse-time validation | Transport (`HttpCache`) | Connect-address guard | Credential |
|-------|----------------------|-------------------------|-----------------------|------------|
| `Trusted` | `validate_index_url(.., PolicyGate::Skip)`: https, no userinfo, no query/fragment; **plus** reject a host whose `classify_host` is `never_a_registry` (FR-008a) | `get_cached_trusted_origin_response`: origin-pinned redirects, `CacheTier::Baseline` | baseline only (`HostClass::never_a_registry`) | yes, if env credential present |
| `WorkspaceDeclared` | `validate_index_url(.., PolicyGate::Enforce(policy))` + same shape checks | `get_cached_pinned_response(authenticated = false, auth_id = None)` | `AddrGuard::WorkspaceDeclared(policy)` | never |

This follows Cargo (`IndexTrust::Trusted` skips policy) rather than npm or NuGet. Swift has no
public default registry, so intranet registries configured by the user are the main use case, and
the user tier is not attacker-controlled.

The rule that `never_a_registry` classes (loopback, link-local, cloud metadata, unspecified,
reserved) are never fetched holds for `Trusted` URLs in both forms:

- A literal IP or a name such as `localhost` is rejected at parse time by FR-008a. This check is
  needed because `PolicyGate::Skip` performs no host check, and hyper never consults the resolver
  for an IP literal.
- A name that resolves to such an address is rejected at connect time by the baseline guard.

A `WorkspaceDeclared` URL is blocked in one of two ways:

- at parse time, by its literal host, through `PolicyGate::Enforce`. This produces a
  `blocked_registries` diagnostic;
- at connect time, when DNS resolves the name to a class the policy blocks. Today this surfaces as
  the policy-specific `HostBlockedByPolicy` message (FR-036).

Known limitation, shared with Cargo's trusted tier: a 401/403 on revalidation of a `Trusted`
authenticated entry serves the stale body. The FR-015 eviction from spec 043 applies to
`CacheTier::Pinned` only, which this path deliberately does not use.

### 3.6 Deliberate deviations from SwiftPM

1. **Credential scope.** Released SwiftPM 6.4.x (`release/6.4.0`..`release/6.4.2`) sends env
   credentials to every host. SwiftPM `main` since swiftlang/swift-package-manager#10507 (merged
   2026-09-09, not in a release branch as of 2026-10-06) binds them to the origins of every
   configured registry across merged tiers, project tier included. This spec is stricter: user-tier
   provenance plus exact full-URL match (§3.3). A project-only registry on a host the user trusts
   gets 401 here where SwiftPM `main` would authenticate. The fix is to add that exact URL to the
   user-level `registries.json`.
2. **Auth type from the user tier only** (SwiftPM merges `authentication` across tiers).
3. **Policy gate on project-tier URLs** (SwiftPM has no such gate).

## 4. Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-001 | THE SYSTEM SHALL compute the user-tier `registries.json` path once, at `SwiftParseContext` construction, per §3.1. It SHALL NOT probe for an existing file among several candidates. WHEN `XDG_CONFIG_HOME` is set but empty or not absolute THE SYSTEM SHALL treat the user tier as unusable (FR-005) | must |
| FR-002 | THE SYSTEM SHALL read the project tier only from `<manifest dir>/.swiftpm/configuration/registries.json`. WHEN the manifest URI has no filesystem path THE SYSTEM SHALL treat the project tier as absent | must |
| FR-003 | THE SYSTEM SHALL classify each tier file as exactly one of `Absent`, `Parsed`, or `Unusable`, in two steps. First `deps_core::fs_probe::metadata(path)`: `Err(NotFound)` gives `Absent`, any other error gives `Unusable`. Only then `MtimeFileCache::get_or_parse`: `None` (not a regular file such as a FIFO or directory, over the size cap, unreadable, or a race with deletion) gives `Unusable`; `Some(Err(_))` (failing FR-004) gives `Unusable`; `Some(Ok(_))` gives `Parsed`. `get_or_parse` alone cannot tell absent from unreadable | must, security |
| FR-004 | THE SYSTEM SHALL decode the fields it consumes with SwiftPM's Codable strictness. The file is invalid when `version` is missing or not `1`, `registries` is missing, any scope key fails the scope grammar, any `authentication` entry has a `type` other than `basic`/`token`, or `supportsAvailability` is not a boolean. A `security` value, if present, SHALL only be required to be a JSON object; its contents SHALL be ignored, so enum values unknown to us never make the file invalid. Unknown keys SHALL be ignored | must, security |
| FR-005 | WHEN either tier is `Unusable` THE SYSTEM SHALL resolve every `id:` dependency in that manifest to `CustomRegistry { url: <canonical scope> }`, never fetch it, and never fall back to the other tier's `[default]`. It SHALL log a warning naming the path and reason, debounced per `(path, mtime)` | must, security |
| FR-006 | THE SYSTEM SHALL merge tiers per §3.1 and resolve a scope as `scoped[scope] ?? default`, matching scopes case-insensitively through `RegistryScope` | must |
| FR-007 | WHEN no entry applies to a scope THE SYSTEM SHALL produce `CustomRegistry { url: <canonical scope> }` and SHALL NOT fetch | must |
| FR-008 | THE SYSTEM SHALL compute `U` and the trust of each resolved URL per §3.2. For a project-tier entry, it SHALL first normalize the URL with shape-only validation. If the result is in `U` the entry is `Trusted`, otherwise it is validated with `PolicyGate::Enforce` | must, security |
| FR-008a | WHEN a `Trusted` URL's host classifies (`net_policy::classify_host`) as `HostClass::never_a_registry` THE SYSTEM SHALL reject the entry as `SwiftRegistryUrlError::NeverARegistryHost(class)`. The entry SHALL resolve to `CustomRegistry { url: <redacted raw> }`, be logged by `tracing::warn!` naming the class, and SHALL NOT be reported through `blocked_registries`, whose text names the policy setting, and that setting cannot unblock these classes. Its `RegistryRejectionClassifier` outcome SHALL be `IntentionallySilent` | must, security |
| FR-009 | WHEN an applicable entry is invalid (not a URL, not https, userinfo, query or fragment, policy-blocked) THE SYSTEM SHALL produce `CustomRegistry { url: <redacted raw> }` and report it through `blocked_registries` or `rejected_registries`. The declaration key SHALL be `scope:<canonical>` or `[default]` | must |
| FR-010 | WHEN an applicable entry is valid THE SYSTEM SHALL produce `AlternateRegistry { index: <normalized URL>, mirrors_crates_io: false }` | must |
| FR-011 | `SwiftFormatter` SHALL return `true` from `resolves_alternate_registry()`. `SwiftRegistry` SHALL override `get_versions_from` and `get_latest_matching_from` to dispatch `AlternateRegistry` to a registered client. WHEN no client is registered THE SYSTEM SHALL return `PackageNotFound` and SHALL NOT fall back to GitHub | must, security |
| FR-012 | `SwiftEcosystem::parse_manifest` SHALL register only the registries this manifest's `id:` dependencies actually resolved to (not every entry of the merged config, so an unused hostile project entry never creates a client) through `register_capped_with_occupied`, rebuilding the occupied client only when its trust or credential digest changed | must |
| FR-013 | THE SYSTEM SHALL read env credentials once, at context construction, through an injected lookup (production: `deps_core::secret::token_from_env`), with the precedence in §3.4 | must |
| FR-014 | THE SYSTEM SHALL attach a credential only to `Trusted` registries (§3.3) and SHALL format it from the user-tier auth type only (§3.4) | must, security |
| FR-015 | THE SYSTEM SHALL hold the formatted header in `SwiftRegistryAuth(Redacted)` with a redacting `Debug`/`Display`, no `Hash`, and a `pub(crate)` constructor. Intermediates SHALL be `Zeroizing`. The `Basic` encoding SHALL use the new shared `deps_core::secret::basic_auth_header`, which `NuGetAuth::new` also migrates to | must, security |
| FR-016 | The binding decision SHALL be one function `bind_credential(url, &user_tier, credential) -> Option<SwiftRegistryAuth>` with no other attach site, marked `TODO(#1459)` as the candidate for a shared predicate | must |
| FR-020 | THE SYSTEM SHALL request `{base}/{scope}/{name}` using the canonical lowercase identity, re-parsed from the dependency name. If re-parsing fails the result is `PackageNotFound`. The request SHALL carry `Accept: application/vnd.swift.registry.v1+json`. The join SHALL produce exactly one `/` whether or not `base` ends in `/` | must |
| FR-021 | THE SYSTEM SHALL route `Trusted` registries through `get_cached_trusted_origin_response` and `WorkspaceDeclared` registries through `get_cached_pinned_response(.., false, None, ..)` (§3.5). The choice SHALL be made by one pure function of `RegistryTrust` that returns a transport kind, which tests assert directly. No other call site selects a transport | must, security |
| FR-022 | THE SYSTEM SHALL map 404 and 410 to `PackageNotFound { registry: "Swift package registry" }` and keep every other non-2xx as `HttpStatus` | must |
| FR-023 | THE SYSTEM SHALL parse `releases` with `parse_json_checked`, skip non-semver keys, set `yanked = problem.is_some()`, and order newest-first through `github::semver_tags_newest_first`. `SwiftRegistry::reports_yanked()` SHALL return `true`, with its comment updated to state that the GitHub path yields only `Available` | must |
| FR-030 | `CachedResponse` SHALL gain `link: Option<String>`, captured together with `ETag`/`Last-Modified` on 200 responses (including the cache-disabled path) and kept on 304. `HttpCache` SHALL add `get_cached_trusted_origin_response` and `get_cached_pinned_response`, both returning `CachedResponse`. The existing byte-returning methods SHALL delegate to the same internal path and map to `.body`, with no behavior change | must |
| FR-032 | `deps_core::pagination` SHALL provide `ListCoverage::from_link_header(Option<&str>)`, returning `Truncated` iff an RFC 8288 link-value carries a `rel` token equal to `next`, compared case-insensitively, quoted or unquoted, possibly among several tokens. `from_link_header` never dereferences the target; only `next_page` resolves it, and only inside the registry's base URL | must |
| FR-034 | THE SYSTEM SHALL follow `Link rel="next"` pages of a release list through `deps_core::pagination::next_page(current, link, trusted) -> NextPage { Last, Next(Url), Rejected }`, which rejects an ambiguous (several distinct targets), empty, unparsable, userinfo-bearing or out-of-prefix target. The next URL SHALL have the same path as the first page, SHALL not repeat an earlier page, and every page SHALL use the same transport and headers as the first. Pages merge by release key, a `problem` on any page marking the release yanked. `get_latest_matching_from` uses the merged list | must |
| FR-035 | WHEN the pages cannot be followed to the last one THE SYSTEM SHALL discard everything fetched and fail with `DepsError::PaginatedListIncomplete { package, registry, reason: PaginationStop }`, with `reason` one of `PageCap` (more than 10 pages, more than 10,000 merged releases, or more than 32 MiB of body bytes), `InvalidNextLink` or `TimeBudget` (15 s for the whole list, only once at least one page was merged; a slow first page is an ordinary transient failure). Its `fetch_failure()` SHALL be `Actionable` with a fixed message. The outcome is remembered per client and package for 90 s so a repeat call fails fast | must |
| FR-036 | WHEN a request fails because the connect-time resolver guard blocked the resolved address THE SYSTEM SHALL return `DepsError::HostBlockedByPolicy { url, class }` instead of a transport error, in every ecosystem. Its `fetch_failure()` SHALL be `Actionable` with a fixed message that names the class and, for `HostClass::never_a_registry` classes, says "never a registry under any policy", otherwise "blocked by registries.workspace_registries policy"; it SHALL contain no remedy. Chains (PyPI, NuGet, Go) keep it when they halt (`DepsError::into_chain_halt`); a Go `\|` chain never lets a later hop's miss overwrite it | must |
| FR-037 | WHEN freshness is enabled THE SYSTEM SHALL fetch `GET {base}/{scope}/{name}/{version}` for the newest 8 non-yanked releases and set `published_at` from `publishedAt`, over the same transport and credential rules. Requests are limited to 4 in flight per registry client and share one 2 s deadline. A `publishedAt` answer (200, or 410 meaning none) is memoized for the process lifetime; any other failure is memoized for 90 s, and only for requests that had started. A missing date never fails the list | must |
| FR-038 | THE SYSTEM SHALL read credentials from the first existing source in the order `SWIFTPM_REGISTRY_*` environment variables, `SWIFTPM_NETRC_DATA`, `~/.netrc` (`SwiftCredentialSource`), with the opt-in Keychain source of FR-044 between `SWIFTPM_NETRC_DATA` and `~/.netrc`. A netrc credential is bound by the registry URL's host (port ignored) and only to `Trusted` URLs, formatted through the same table as the environment credential. `deps_core::netrc` follows SwiftPM's grammar; `SWIFTPM_NETRC_DATA` uses first-match, case-sensitive hosts and honors `default`; `~/.netrc` uses last-match, case-insensitive hosts, is re-read when its mtime changes, treats an absent, unreadable or invalid file as no credential, and ignores its `default` entry on macOS | must |
| FR-040 | `Package.resolved` v2/v3 `kind` SHALL decode into `PinKind { RemoteSourceControl (default when missing), LocalSourceControl (alias "fileSystem"), Registry, Unrecognized (serde other) }`. `Registry` maps to `ResolvedSource::Registry { url: "", checksum: "" }` (SwiftPM writes `location: ""`), `LocalSourceControl` to `Path`, and `Unrecognized` is skipped with a debug log. Previously an unknown kind became Git | must |
| FR-041 (superseded by #1759: `WatchedConfig` path suffix `.swiftpm/configuration/registries.json`) | Swift SHALL declare the basename `registries.json` in both `watched_config_filenames()` and `routing_affecting_watched_configs()`, with a `TODO` pointing at the path-suffix follow-up (Out of Scope). No `deps-core` or `deps-lsp` watcher change is made | must |
| FR-042 | `deps-engine` `register_ecosystems` SHALL construct Swift with `SwiftEcosystem::with_context` and add `EcosystemId::Swift` to `workspace_registry_ecosystems` | must |
| FR-043 | The parser SHALL drop `TODO(#1691)` and store `CustomRegistry.url` as the canonical scope | must |
| FR-044 | WHEN `registries.swift_keychain_credentials` is `enabled` on macOS, no environment or `SWIFTPM_NETRC_DATA` credential applies and the registry is `Trusted` (user-declared) THE SYSTEM SHALL look the credential up in the Keychain through `/usr/bin/security find-internet-password -s <host> -r htps [-P <port>]` (`-P` only for an explicit URL port), then read the account and the secret (`-g`, parsed from stderr, because `-w` prints non-ASCII secrets as bare hex), and format it through the same table as the environment credential (`user == "token"` heuristic included). The lookup SHALL run at fetch time in a detached single-flight task per host with one 10-minute budget, never at parse time, serialized so only one prompt is open at a time (the budget starts when the lookup gets the dialog slot), and never in offline mode. A switch between with-credential and without-credential for a registry (lookup to found, any setting change) SHALL drop its cached release lists, except offline. Outcomes SHALL be memoized per host: found for the process lifetime, not found for 5 minutes, refused (any `security` exit other than 44 and 36) until the setting is toggled, timeout and exit 36 never; a `security` spawn failure counts as refused. The first applicable source wins as in SwiftPM, so an enabled Keychain means `~/.netrc` is not read and a Keychain miss does not fall through to it. WHEN no outcome is `Found` THE SYSTEM SHALL send no credential, and a `401` SHALL NOT start a new lookup. WHEN the answer arrives after the waiting request gave up THE SYSTEM SHALL re-parse open Swift documents once so the credential is used. Disabling the setting SHALL drop memoized secrets immediately and abort in-flight lookups; a `didChangeConfiguration` payload without `registries` resets it to `disabled`. The secret SHALL never be logged or passed as an argument; the account name is passed with `-a`. `deps-cli` SHALL force the setting to `disabled` with a warning. Where several items match, `security` returns the first, whereas SwiftPM picks the most recently modified | must |

## 5. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Credential-shaped values live only in `SwiftCredential` (fields `Redacted`), `Netrc` and `NetrcLogin` (`Redacted`), and `SwiftRegistryAuth`. They never appear in logs, `Debug` output, hover, diagnostics or cache keys |
| NFR-002 | Security | An `id:` package name is never sent to GitHub, OSV, deps.dev or any registry other than the one resolved by FR-006 |
| NFR-003 | Reliability | Manifests without `id:` dependencies, machines without `registries.json`, and every non-Swift ecosystem behave byte-identically to today, apart from the FR-040 unknown-kind change. The `deps-core` additions (FR-015, FR-030, FR-032, FR-034) are additive; NuGet's `Basic` header bytes stay identical after its migration to `basic_auth_header` |
| NFR-004 | Performance | `parse_manifest` keeps the no-real-`.await` invariant. Config reads go through `MtimeFileCache` |

## 6. Data Model

| Entity | Crate | Description |
|--------|-------|-------------|
| `RegistryScope` | deps-swift | Canonical ASCII-lowercase scope newtype, `parse(&str) -> Option<Self>` on the SE-0292 grammar; the single matching key for scopes |
| `RegistryIdentity<'a>` (extended) | deps-swift | Adds `scope_key() -> RegistryScope` and `canonical() -> String` (lowercase `scope.name`) |
| `RegistryTrust` | deps-swift | `Trusted \| WorkspaceDeclared`, exhaustive, a function of `(URL, U)` |
| `SwiftRegistryUrl` | deps-swift | Normalized URL plus `RegistryTrust`. Own newtype, not `ValidatedRegistryUrl`, because the latter cannot skip the policy (same reason as Cargo's `RegistryIndex`, #959 D1) |
| `SwiftRegistryUrlError` | deps-swift | `Url(IndexUrlError) \| NeverARegistryHost(HostClass)`. Implements `BlockedHostReason` (delegating for `Url`, `None` for `NeverARegistryHost`) and `RegistryRejectionClassifier` (`IntentionallySilent` for `NeverARegistryHost`) |
| `RegistryHostKey` | deps-swift | Lowercase punycode host plus explicit non-default port, built only by parsing `https://{key}` through `url` (so `h:443` equals `h`) |
| `SwiftAuthType` | deps-swift | `Basic \| Token` (serde lowercase) |
| `RawRegistries` | deps-swift | `default: Option<String>`, `scoped: HashMap<RegistryScope, String>`, `authentication: HashMap<RegistryHostKey, SwiftAuthType>`; `security` is only checked to be an object, then ignored |
| `TierFile` | deps-swift | `Absent \| Parsed(Arc<RawRegistries>) \| Unusable(RegistriesConfigError)` |
| `RegistriesConfigError` | deps-swift | `Unreadable \| Malformed { line, column } \| UnsupportedVersion(u32) \| InvalidScopeKey \| SecurityNotAnObject \| InvalidXdgConfigHome`. Payload-free, because serde messages can echo values |
| `SwiftRegistriesConfig` | deps-swift | Merged view: `resolve_source_for`, `blocked_class_for`, `rejected_reason_for`, `resolved_registry_for(scope) -> Option<&ResolvedSwiftRegistry>` |
| `SwiftCredential` | deps-swift | `Token(Redacted) \| Login { username: Redacted, password: Redacted }` |
| `SwiftRegistryAuth` | deps-swift | Pre-formatted header, see FR-015 |
| `ResolvedSwiftRegistry` | deps-swift | `{ url: SwiftRegistryUrl, auth: Option<SwiftRegistryAuth> }` |
| `SwiftParseContext` | deps-swift | `{ policy, cache: Arc<SwiftRegistriesCache>, user_config: UserConfigPath, credential: Option<Arc<SwiftCredentialSource>> }` |
| `SwiftCredentialSource` | deps-swift | `Environment(SwiftCredential) \| NetrcData(Arc<Netrc>) \| NetrcFile { path, default_entry, .. }` (FR-038) |
| `PackageRegistryClient` | deps-swift | SE-0292 client: `list_releases(&RegistryIdentity, PublishedAtLookup) -> Result<Vec<SwiftVersion>>`. Follows pages (FR-034) and fails with `PaginatedListIncomplete` when it cannot (FR-035) |
| `PinKind` | deps-swift | See FR-040 |
| `CachedResponse.link` | deps-core | See FR-030 |
| `ListCoverage::from_link_header` | deps-core | See FR-032 |
| `DepsError::PaginatedListIncomplete` | deps-core | See FR-035; `Actionable` with a fixed message |
| `DepsError::HostBlockedByPolicy` | deps-core | See FR-036; `Actionable` with a fixed message |
| `secret::basic_auth_header` | deps-core | `(username, password) -> Redacted`, moved from `NuGetAuth::new` |

## 7. Edge Cases

| Scenario | Expected Behavior |
|----------|-------------------|
| No `registries.json` anywhere | `CustomRegistry { canonical scope }`, no request (FR-007) |
| Project file is a FIFO, a directory, unreadable, or over 8 MiB | Tier `Unusable`; all `id:` dependencies unresolved, with no fallback to the user `[default]` (FR-005) |
| Project file has `"version": 2`, a bad scope key, `"type": "oauth"`, or `"security": 5` | Whole file `Unusable` (FR-004/005) |
| `security.default.signing.onUnsigned` holds a value newer than SwiftPM 6.4 | Ignored; the file stays `Parsed` (FR-004) |
| Project `[default]` and user scoped `acme` both present | `acme.*` uses the user entry; other scopes use the project `[default]` |
| `.package(id: "Acme.Net")` with key `"acme"` | Matches (FR-006); request path `/acme/net` |
| Project entry `http://...`, `https://u:p@...`, or `https://h/x?y` | `CustomRegistry { redacted raw }` plus a `rejected_registries` diagnostic |
| Project entry `https://10.0.0.5` under `public_only` | `blocked_registries` diagnostic, no request |
| Project entry hostname resolving to RFC1918 under `public_only` | Refused by the pinned guard; `HostBlockedByPolicy` with the "blocked by registries.workspace_registries policy" message (FR-036) |
| User entry hostname resolving to RFC1918 under `public_only` | Fetched (`Trusted` is exempt) |
| User entry `https://127.0.0.1`, `https://169.254.169.254` or `https://localhost:8443` | Rejected at parse time (FR-008a): `CustomRegistry`, warning naming the class, no request |
| User entry hostname that resolves to loopback or cloud metadata | Refused at connect time by the baseline guard; `HostBlockedByPolicy` with the "never a registry under any policy" message (FR-036) |
| User tier lists a public `[default]` and a private scope, `SWIFTPM_REGISTRY_TOKEN` set | The token is sent to both (§3.3 warning) |
| Project entry equal to a user URL | `Trusted`: exempt, credential attached |
| Project entry on a trusted host with a different path | `WorkspaceDeclared`: gated, no credential |
| User `authentication` lists a host but no user registry URL on it | No trust anchor; the entry only affects formatting |
| Only `SWIFTPM_REGISTRY_LOGIN` set | No credential, plus a warning naming the variable |
| Registry redirects cross-origin | Refused by the origin-pinned transport (error), never followed with credentials |
| Response carries `Link: <..>; rel="next"` | The next page is followed and merged (FR-034); an unusable link, a cap or the time budget gives `PaginatedListIncomplete` (FR-035) |
| `SWIFTPM_NETRC_DATA` or `~/.netrc` holds a machine for a trusted registry host | `Login` credential sent to that host only (FR-038) |
| Release metadata has no `publishedAt`, or the request fails | The version list is unaffected; no date (FR-037) |
| Response carries `Link` with only `rel="latest-version"` or `rel="canonical"` | Not truncated; the list is used |
| Release has `problem` | Version marked yanked |
| Same registry URL opened from two workspaces with different project files | One client; trust and credential depend only on `(URL, U, env)`, so no rebuild flapping |
| Unrelated `registries.json` elsewhere in the workspace changes | Extra reparse and refetch of open Swift documents; results unchanged (FR-041 interim) |
| `Package.resolved` pin with no `kind` | `RemoteSourceControl` (current behavior) |
| `Package.resolved` pin with an unknown kind | Skipped (FR-040) |

## 8. Success Criteria / Acceptance Tests

| ID | Test | Verifies |
|----|------|----------|
| SC-001 | Tier path selection: macOS cfg path; Linux XDG set, unset, empty, relative; no home dir | FR-001 |
| SC-002 | Tri-state reads: missing gives `Absent`; FIFO, directory, oversized and unreadable give `Unusable`, all via the stat-then-`get_or_parse` sequence; with a user `[default]` present, an `Unusable` project tier still resolves to `CustomRegistry` | FR-003, FR-005 |
| SC-003 | Strict decode table: version, registries, scope key, auth type, `supportsAvailability`; `security` as a non-object makes the file `Unusable`; `security` with unknown enum values leaves it `Parsed` | FR-004 |
| SC-004 | Merge quirk (user scoped beats project default); case-insensitive scope | FR-006 |
| SC-005 | Trust table: user entry; project entry equal to a user URL; project entry on the same host with another path; host only in `authentication`; a public user `[default]` plus a private scope both receive the credential | FR-008, FR-014, §3.3 |
| SC-005a | `Trusted` literal hosts `127.0.0.1`, `[::1]`, `169.254.169.254`, `0.0.0.0`, `localhost` are rejected at parse time, with no `blocked_registries` occurrence; RFC1918 literals in the user tier are accepted | FR-008a |
| SC-006 | Formatting table (5 rows) with user-tier type; a project-tier `authentication` entry has no effect on the header or digest | §3.4, FR-014 |
| SC-007 | Env precedence and partial vars via the injected lookup; `debug_redaction_conformance!` for `SwiftCredential` and `SwiftRegistryAuth` | FR-013, FR-015, NFR-001 |
| SC-008 | Mockito: `match_header` on Accept; Authorization present only when `Trusted` and a credential is set; lowercase path; base with and without a trailing `/`; 404 and 410 give `PackageNotFound`; `problem` gives yanked; unsorted and non-semver input | FR-020..FR-023 |
| SC-009 | Cross-origin redirect: the pinned and trusted-origin transports return an error | FR-021 |
| SC-010 | Router: an unregistered `AlternateRegistry` returns `PackageNotFound` and a GitHub mock records 0 hits; `CustomRegistry` is never fetched | FR-011, NFR-002 |
| SC-011 | Transport selection asserted in deps-swift through the pure FR-021 function (`Trusted` gives the trusted-origin transport, `WorkspaceDeclared` gives pinned), plus mockito round trips on both. The RFC1918 connect-time behavior of each transport stays covered by the existing deps-core synthetic-resolver tests (`TestLookup` is `cfg(test)`-private to deps-core) | FR-021 |
| SC-012 | `from_link_header` and `next_page` grammar cases (quoted, unquoted, multi-token `rel="next last"`, mixed case, several link-values, `latest-version` only, absent header, several distinct targets, empty target, foreign origin, other path, userinfo). `HttpCache` captures `link` on 200 and keeps it on 304. Mockito: a 3-page merge, the page, count, byte and time caps, cycles (including late-page ones), a missing later page, Authorization on every page when `Trusted`, and the failure memo | FR-030, FR-032, FR-034, FR-035 |
| SC-017 | `HostBlockedByPolicy` through `send_error` with a synthetic lookup (gated and never-a-registry class), an `HttpCache` round trip on a `localhost` name, stale-while-revalidate serving a warm entry, PyPI/NuGet/Go chain tests, the Go `\|` rule | FR-036 |
| SC-018 | `publishedAt`: dates on the newest 8 non-yanked releases only, memoized across calls, failures never fail the list, a hanging request does not discard finished ones, requests without a permit are not memoized | FR-037 |
| SC-019 | netrc grammar table (quotes, comments, account, drops, contiguity, IPv6 hosts), source precedence, `default` per platform, binding to `Trusted` only, mtime-driven re-read, unreadable file warns once, redaction conformance | FR-038 |
| SC-013 | Lockfile: registry pin, `localSourceControl`, legacy `fileSystem`, missing kind, unknown kind skipped | FR-040 |
| SC-014 (superseded by #1759: `watched_configs()`) | Swift's `watched_config_filenames()` and `routing_affecting_watched_configs()` both contain `registries.json` | FR-041 |
| SC-017 | Fake `security` backend: found, not found (memoized 5 min), refused (memoized until toggle), timeout (not memoized), toggle purge, workspace-declared registry never receives the credential, precedence env > `SWIFTPM_NETRC_DATA` > Keychain > `~/.netrc`; live macOS throwaway item for a `.invalid` host found without a prompt. The access prompt (deny, cancel, locked keychain) is untested | FR-044 |
| SC-015 | `is_url_source(AlternateRegistry)` is `false` (completion never rewrites an `id:` literal); ecosystem conformance; engine setup includes Swift | FR-042 |
| SC-016 | Live: project `[default]` = `https://tuist.dev/api/registry/swift`; `apple.swift-nio` and `Apple.Swift-NIO` from `2.0.0` show the latest 2.x; removing the config produces no request in the log | US-001, Registry Integration Gate |

## 9. Open Questions

None blocking. Every critic finding from both rounds (S1..S5, M1..M9, N1..N7) is resolved in §3 and
§4. The deferred items are listed under Out of Scope and become follow-up issues when #1691 closes:

1. SCM-to-registry swizzling (#1757).
2. #1459: shared credential-provenance predicate across deps-cargo, deps-nuget and deps-swift.
3. Path-suffix watched-config entries, so that Swift watches only
   `.swiftpm/configuration/registries.json`.
4. The `latest-version` link.

Items for `Link rel="next"` pages (#1754), `publishedAt` (#1756), netrc (#1755) and
`HostBlockedByPolicy` (#1758) shipped in the follow-up PR.

## 10. Agent Boundaries

### Always
- Run the full check suite (`cargo +nightly fmt --all -- --check`, clippy `-D warnings` with
  `--all-features`, `nextest --workspace --all-features`, and the rustdoc `-D warnings` gate).
- Verify against a live SE-0292 registry (SC-016) before the PR.
- Update `CHANGELOG.md`, `book/src/ecosystems/swift.md` (config paths, trust rule, the §3.3
  single-credential warning, the §3.6 deviations, policy behavior, the pagination limitation,
  follow-ups), `crates/deps-swift/README.md`,
  `.local/testing/coverage.md`, and `.local/testing/playbooks/swift.md`.

### Ask First
- Changing any existing `HttpCache` byte-returning method's behavior (FR-030 only adds delegation).
- Any `deps-core` change beyond FR-015, FR-030, FR-032 and FR-034, in particular a `Registry` trait,
  `PackageVersions`, diagnostics or watcher change.
- Extracting the shared credential-provenance predicate (#1459).

### Never
- Attach a credential to a `WorkspaceDeclared` registry, or derive the auth type from the project
  tier.
- Fall back to GitHub, or to the other tier, when a registry is unregistered or a tier is
  `Unusable`.
- Dereference a `Link` header URL.
- Log or render any `Redacted` value.

## 11. See Also
- [[043-nuget-feed-authentication/spec|043]]: full-URL credential binding (§3.2) and the pinned transport.
- [[023-cargo-custom-registries/spec|023]]: `IndexTrust::Trusted` policy exemption and `RegistryIndex`.
- [[032-npm-npmrc-registry-support/spec|032]]: `AlternateRegistry` router and registration.
- SwiftPM `Documentation/PackageRegistry/{Registry.md,PackageRegistryUsage.md}`;
  `Sources/PackageRegistry/RegistryConfiguration.swift`, `RegistryClient.swift`;
  `Sources/Basics/AuthorizationProvider.swift`; swiftlang/swift-package-manager#9925, #10507.

---
aliases:
  - Swift SCM-to-registry swizzling
  - Registry identity for SCM dependencies
  - SE-0292 identifiers lookup
tags:
  - sdd
  - spec
  - enhancement
  - ecosystem/swift
  - security
  - deps-core
  - priority/p4
created: 2026-10-21
status: specify
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[plan]]"
  - "[[tasks]]"
  - "[[077-swift-registry-client/spec|077 Swift registry client]]"
  - "[[084-unified-registry-trust-rule/spec|084 Unified registry trust rule]]"
  - "[[086-git-ref-probe-branch-evidence/spec|086 Git-ref probe infrastructure]]"
---

# Feature: SwiftPM SCM-to-registry swizzling (registry identity for `url:` dependencies)

> [!info] Metadata
> **Author**: sdd (architect design 2026-10-21, critic-reviewed over several rounds)
> **Type / priority**: enhancement, security-sensitive (sends repository URLs to a registry), P4
> **Issue**: #1757
> **Branch**: suggested `feat/1757-swift-scm-to-registry`
> **Depends on**: [[086-git-ref-probe-branch-evidence/spec|spec 086]] (`ProbePhase`, `ProbeReport`/`ProbeEffect`, typed `RefreshEvent`; its section 6 is the reuse interface) and #1873 (`NormalizedName` keys). May ship as its own PR after 086.
> **Phase**: specify, plan, tasks. Open `[NEEDS CLARIFICATION]`: 0.

> [!abstract]
> SwiftPM can replace a `.package(url:)` dependency by a registry identity (`--replace-scm-with-registry`,
> `--use-registry-identity-for-scm`). deps-lsp, which resolves `.package(id:)` since spec 077, ignores this and keeps
> showing source-control tags. This spec adds an opt-in setting `registries.swift_scm_to_registry = "replace"`. Under it,
> an eligible `url:` dependency is looked up through the trusted user-tier default registry's SE-0292 `identifiers`
> endpoint and, when exactly one identity matches, is parsed as an `id:` dependency with provenance. All routing, auth,
> trust, policy gating and lockfile matching of `id:` dependencies are reused unchanged.

## 1. Overview

### Problem Statement

A team that builds with SCM-to-registry replacement resolves `url:` dependencies from its registry, so versions shown from
GitHub tags can differ from what SwiftPM resolves. Detection cannot come from files: the flags exist only on the
`swift`/`xcodebuild` command line. Therefore the signal is explicit configuration.

### Goals

1. `registries.swift_scm_to_registry` (`Disabled` default, `Replace`) swaps eligible `url:` dependencies to registry identities.
2. Hover shows both the registry identity and the source repository's advisories; vulnerability, license and lock behavior of a swizzled dependency do not regress.
3. No credentials leave the machine: repository URLs are credential-stripped, and only the operator-owned (user-tier) trusted default registry is ever asked.
4. Deterministic and convergent: LSP and CLI show the same result for the same registry answers, with no parse/refetch flapping.

### Why no `UseIdentity` value

`--use-registry-identity-for-scm` keeps SCM as the version source and its `Package.resolved` pins keep `location` = URL, which
the lockfile parser already maps through `url_to_identity`. Nothing observable changes, so an enum value would be a no-op.

### Out of Scope

> [!danger] Excluded
> - Reading the Xcode default `IDEPackageDependencySCMToRegistryTransformation` (macOS/Xcode only, needs a process spawn); follow-up F-5 (optional).
> - Branch and revision requirement forms: never eligible (a registry has only versions), as in SwiftPM.
> - scp-like and ssh URLs: not eligible. This diverges from SwiftPM, which swizzles them; documented in the book.
> - Consulting project-tier `registries.json` for swizzling (attacker-controlled; deliberate deviation from SwiftPM, spec 084 trust rule).
> - Registry-pin in-use matching as a separate feature (F-4): covered by the `id:` substitution, see FR-018; no work needed unless a gap is found.
> - A `Route::Swizzle`, formatter `can_resolve_source` override, fetch-time lookup mapping, `Package.resolved` network bridging (rejected designs).

## 2. User Stories

### US-001: Show registry versions for a swizzled dependency
AS A Swift developer whose build replaces SCM with the registry
I WANT hover, hints and diagnostics to use the registry's versions for `.package(url: "https://github.com/apple/swift-nio", from: "2.0.0")`
SO THAT the editor matches what SwiftPM resolves.

```
GIVEN mode Replace, a trusted user-tier [default] registry, and identifiers?url=https://github.com/apple/swift-nio answering exactly ["apple.swift-nio"]
WHEN the manifest is opened
THEN the dependency is parsed as id: "apple.swift-nio" served by that registry, hover shows
  "Resolved via registry identity apple.swift-nio (from https://github.com/apple/swift-nio)"
  and the dependency's name_range and version_range are unchanged
```

### US-002: No new false positives
```
GIVEN a url: dependency whose URL is not in the registry (404/empty), several identifiers, an invalid identity, or a failed lookup
THEN it stays on the source-control path exactly as today; no "Unknown package" is produced
GIVEN Failed (transport, 5xx, rate limit)
THEN the same plus an Information notice "registry identity lookup failed; showing source-control versions"
```

### US-003: Vulnerabilities keep firing
```
GIVEN an OSV advisory on github.com/apple/swift-nio
THEN it renders both before and after Replace swizzles the dependency to apple.swift-nio
```

## 3. Functional Requirements (EARS)

### 3.1 Configuration and trust

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL add `registries.swift_scm_to_registry: ScmToRegistry { Disabled (default), Replace }` (snake_case serde enum, `#[serde(default)]`) next to `swift_keychain_credentials` in `policy_config.rs`; the CLI uses the same `PolicyConfig` | must |
| FR-002 | THE SYSTEM SHALL add a `PolicyConfigDiff` entry for it; WHEN the mode changes, THE SYSTEM SHALL re-parse every open Swift document (not only re-fetch) | must |
| FR-003 | THE SYSTEM SHALL add `swift_scm_to_registry` to deps-cli `ignored_sections` so an auto-discovered `deps.toml` gets the warning | must |
| FR-004 | THE SYSTEM SHALL use only the user-tier `[default]` registry, and only when it is `RegistryTrust::Trusted`; project-tier `registries.json` SHALL NEVER be consulted for lookups. WHEN `Replace` is set without a trusted user-tier default, THE SYSTEM SHALL log once with `tracing::warn!` and behave as `Disabled` | must |
| FR-005 | The scope of a returned identity SHALL route by the user-tier scope table or that default; an identity whose scope does not resolve in the user tier yields the SCM form | must |

### 3.2 Eligibility, URL handling and the identifiers lookup

| ID | Requirement | Priority |
|----|------------|----------|
| FR-006 | A dependency is eligible only if its typed `SwiftRequirementForm` is `Version` (`from:`, `upToNextMajor`/`upToNextMinor`, `exact`, ranges) on an `https` or `http` URL. `branch:` and `revision:` forms (which already emit `Git { rev: Some(_) }`) and scp/ssh URLs are never eligible | must |
| FR-007 | `ScmLookupUrl::parse(written) -> Option<Self>` SHALL be the only constructor. It accepts `https`/`http` only, removes userinfo, query and fragment, rejects credential-shaped path segments, and canonicalizes (lowercase host only, strip trailing `/` and `.git`; the repository path keeps its case). The stripping lives in deps-core as `redact::strip_url_credentials(raw) -> Option<url::Url>`, reusing `segment_has_credential_colon`. It SHALL also reject percent-encoded credential segments, `@` in the path, and bare token-prefixed path segments (reusing `TOKEN_PREFIXES`) | must |
| FR-008 | The request SHALL be `GET {default}/identifiers?url=<pct-enc>` with `Accept: application/vnd.swift.registry.v1+json`, sending the credential-stripped *written* URL; the memo is keyed by the canonical form. WHEN the written URL differs from the canonical one and the answer is `NotRegistered`, THE SYSTEM SHALL send exactly one retry with the canonical form | must |
| FR-009 | The lookup answer is the typed `IdentityLookup { Unique(RegistryIdentity), Ambiguous, NotRegistered, Rejected, Failed }`. Only strings passing `RegistryIdentity::parse` are stored; a server string that fails it is `Rejected` (SCM form, debug log). 404 or empty is `NotRegistered`; several identifiers is `Ambiguous`. Classification of the answer list is a single linear pass (`classify_identifiers`): `Ambiguous` at the second distinct identity, or when the list exceeds 256 entries | must |
| FR-010 | Identifiers lookups SHALL run outside the 086 `ProbeAllowance`, under the Swift registry's existing `FetchConcurrency`, `FetchTimeout`, that host's `RateLimitGate` and breaker, single-flight per `ScmLookupUrl`, and at most one refresh per TTL (1 h) per URL. Each lookup replaces a GitHub tags fetch rather than adding one. Timeout and concurrency come from the live fetch settings (`cache.fetch_timeout`, `cache.max_concurrent_fetches`) set on the registry handle for both the LSP and the CLI (`set_fetch_limits`); there is no fixed wait. Misses are started `fetch_concurrency` at a time and each is awaited up to its own timeout, so LSP and CLI end on the same forms; stale refreshes are bounded to `concurrency/2` per pass | must |
| FR-011 | Each per-URL lookup SHALL be spawned detached into the per-URL single-flight, so that aborting or superseding a debounced change task drops only the waiter and never cancels the request before the memo is written | must |

### 3.3 The memo and the decision

| ID | Requirement | Priority |
|----|------------|----------|
| FR-012 | `ScmIdentityMemo` (shared through the Swift registry) SHALL be keyed by `MemoKey(lookup registry URL, canonical ScmLookupUrl)` and its entries SHALL hold `{ answer: IdentityLookup, fetched_at, last_read }`, with a `generation: u64` that advances only when the unique identity a key resolves to appears, changes or disappears (an `Ambiguous`/`NotRegistered`/`Failed` flip between non-unique answers does not advance it). A read returns the last known answer even when stale; staleness (TTL 1 h) only schedules a background refresh. A refresh returning the same answer, or `Failed`, changes nothing | must |
| FR-013 | Eviction SHALL be by idleness: `last_read` older than 24 h, plus a hard cap of 4096 (oldest-read first). Every parse of an open document refreshes `last_read` | must |
| FR-014 | THE SYSTEM SHALL decide the dependency form only through the pure `swizzle_decision(SwizzleInput) -> SwiftForm`, called by both the parser and the probe. `SwiftForm { Scm, RegistryIdentity { identity, index } }`. It returns `RegistryIdentity` only when mode is `Replace`, a trusted user-tier default exists, the form is `Version`, `ScmLookupUrl` parsed, and the answer is `Unique(id)` whose scope resolves in the user tier. Every other combination returns `Scm` | must |
| FR-015 | WHEN the parser emits the registry form, THE SYSTEM SHALL produce an `id:` dependency: `name` = registry identity (`scope.name`), `source` = `AlternateRegistry { index }`, `SwiftDependency.origin: SwiftOrigin::Swizzled { scm: ScmLookupUrl }` (otherwise `Declared`), `name_range`/`version_range` unchanged. The parser performs no network I/O and consults only the memo | must |

### 3.4 Probe phases, reparse, fan-out

| ID | Requirement | Priority |
|----|------------|----------|
| FR-016 | Swift `background_probes(parse_result, ProbePhase::PreFetch)` SHALL await the identifiers lookups for memo misses of eligible URLs (stale entries refresh in the background and are never awaited). It returns `ProbeEffect::Reparse` only when `swizzle_decision(..)` for some eligible dependency differs from the form that dependency was parsed with, whoever warmed the memo. With no eligible dependency or a mode other than `Replace`, PreFetch is a no-op. WHEN the registry refuses a swizzled dependency because the alternate-registry limit is exhausted, THE SYSTEM SHALL revert that dependency to the SCM form (`SwiftDependency::revert_to_scm`) and the probe's effective form SHALL agree, so no `Reparse` fires on every edit | must |
| FR-017 | The flow SHALL be, on both surfaces: parse, `PreFetch`, reparse on `Reparse` (at most once), registry fetch, `PostFetch`, classify. Parses carry a typed `ParseTrigger { Content, Config, Memo }`: `PreFetch` and probes run for `Content` (open/change) and `Config` (policy/watched-file reparse via `reparse.rs`) and NEVER for a `Memo`-triggered reparse (`Reparse` result or `ReparseOpenDocuments`). In the LSP `PreFetch` is awaited before the registry fetch | must |
| FR-018 | WHEN the memo generation changes, THE SYSTEM SHALL emit `RefreshEvent::ReparseOpenDocuments { generation }`, coalesced to one reparse per 1 s window per ecosystem; a document applies a given generation at most once per content version. Because the substituted dependency is an `id:` dependency, a `Package.resolved` registry pin (keyed by identity, lowercased `NormalizedName`) matches it and in-use versions work with no extra code (F-4 is therefore not needed) | must |
| FR-019 | WHEN an eligible lookup does not complete (timeout, gate open), THE CLI SHALL print one stderr note `N registry identity lookups incomplete; using source-control versions`, and the result is `Scm` for those dependencies. With `Failed`, the dependency-level Information notice of US-002 SHALL be emitted (`DiagnosticKind::Notice`). The `Failed` notice is emitted only when a trusted default exists | must |

### 3.5 Vulnerability, license and display parity

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | THE SYSTEM SHALL add to deps-core `OsvNaming` the hook `fn public_content<'d>(&self, dep: &'d dyn Dependency) -> Option<PublicContent<'d>>`, with `PublicContent { name: Cow<'d, PackageName> }`; the lifetime is tied to `dep` so `Borrowed(dep.name())` compiles. The default returns `source_is_public_registry_content(&dep.source()).then(|| PublicContent { name: Borrowed(dep.name()) })` so every other ecosystem is bit-identical. It replaces the source gate at exactly five sites: `osv/types.rs:2328` (`vulnerability_keys`), `classify/osv.rs:352` (`build_scan_targets`), `classify/osv.rs:467` (`classify_dep_for_check_targets`, phase B), `lsp_helpers/mod.rs:1867` (stale-skip in `upgrade_status_to_verdict`), `classify/license.rs:195` (`tier3_license_targets`) | must |
| FR-021 | The Swift override SHALL return `Owned(owner/repo)` for `Swizzled { scm }` on a GitHub host, derived from `url_to_identity(scm)` and keeping the repository path's case (OSV `SwiftURL` is case-sensitive; `ScmLookupUrl` lowercases only the host); everything else uses the default. Swift `osv_package_name` builds `github.com/{public_content.name}` and never uses `dep.name()` (the registry identity) for a swizzled dependency | must |
| FR-022 | Tier-3 license results SHALL be requested under `public_content.name` (`owner/repo`) but stored under the dependency's own key `PackageKey::new(dep.name(), formatter).normalized()` (`scope.name`, consistent with the #1873 re-key), so hover and diagnostics find them and a configured deny-list fires | must |
| FR-023 | WHILE a swizzled dependency's latest/candidate OSV check (phase B) is not yet complete, its latest verdict SHALL be `Unverified`, never `NotApplicable` (the #1517 class) | must |
| FR-024 | THE SYSTEM SHALL leave typosquat, GOSSIP, trust, fetch-in-use and Cargo/Deno uses on the source gate (`deps_dev_system(Swift) == None`, so none of them can see a swizzled dependency). The conformance suite (`conformance.rs`, next to `:749`) SHALL assert for every ecosystem that a fixture dependency in default provenance has `public_content(dep).is_some() == source_is_public_registry_content(&dep.source())` | must |
| FR-025 | Hover on a swizzled dependency SHALL show the provenance line `Resolved via registry identity <scope.name> (from <scm, redacted>)` and the source repository's advisories in the vulnerability section; document links keep using the written URL | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Userinfo, query and fragment never reach the registry: `https://oauth2:TOKEN@gitlab.example.com/x.git?private_token=y` reaches the mock as `https://gitlab.example.com/x` (mock asserts no `TOKEN`); only a trusted operator-owned registry is asked; tokens follow the existing netrc/keychain/env binding and `HostBlockedByPolicy` gate |
| NFR-002 | Convergence | The decision is a pure function of mode, trust and memo; after one reparse it is a fixed point. Removing the trusted default while a `Unique` entry stays in the memo, then N probe cycles, yields zero `Reparse` and zero events |
| NFR-003 | Stability | An expired or evicted memo entry never flips the parse form to SCM and back (stale-while-revalidate); a transient `Failed` never overwrites a known answer |
| NFR-004 | Determinism | For given registry answers the CLI output equals the LSP output; a CLI run awaits all lookups |
| NFR-005 | Responsiveness | The parser performs no network I/O; handlers stay non-blocking; with no eligible dependency or mode other than `Replace` latency is unchanged |
| NFR-006 | Type safety | `ScmToRegistry`, `SwiftOrigin`, `SwiftForm`, `IdentityLookup`, `SwiftRequirementForm`, `ProbePhase`, `RefreshEvent` are exhaustive (no `_ =>`); `ScmLookupUrl` and `RegistryIdentity` have private constructors |
| NFR-007 | Bounded memory | Memo capped at 4096 entries |
| NFR-008 | Documentation | The book `swift.md` documents the setting, the Xcode default value mapping, the trust deviation (project tier never consulted), the scp/ssh deviation, and the first-open behavior |

## 5. Typed API sketch

```rust
pub enum ScmToRegistry { Disabled, Replace }
pub enum SwiftRequirementForm { Version, Branch, Revision }          // set by the parser
pub enum SwiftOrigin { Declared, Swizzled { scm: ScmLookupUrl } }
pub enum IdentityLookup { Unique(RegistryIdentity), Ambiguous, NotRegistered, Rejected, Failed }
pub enum SwiftForm { Scm, RegistryIdentity { identity: RegistryIdentity, index: RegistryIndexUrl } }
pub struct SwizzleInput<'a> { pub mode: ScmToRegistry, pub lookup: Option<&'a TrustedLookupRegistry>,
    pub form: SwiftRequirementForm, pub scm: Option<&'a ScmLookupUrl>, pub answer: Option<&'a IdentityLookup> }
pub fn swizzle_decision(input: SwizzleInput<'_>) -> SwiftForm;
pub struct PublicContent<'d> { pub name: Cow<'d, PackageName> }
```

## 6. Reuse of spec 086 (interface, not modification)

Consumes: `ProbePhase::PreFetch`, `ProbeReport`/`ProbeEffect::Reparse`, `Ecosystem::background_probes`, the typed `RefreshEvent` (with `ReparseOpenDocuments { generation }`), the coalesce-latest `ProbeSlot` single-flight, and the `NormalizedName` key convention. Does not use `ProbeRef` or `ProbeAllowance` (identifiers lookups are bounded by FR-010).

## 7. Edge Cases

| Scenario | Expected |
|----------|----------|
| Memo TTL expiry | Stale answer used, background refresh, no flicker |
| Document B parsed before A warmed the URL | B's next probe: decision differs from parsed form, `Reparse`; and the generation event reparses open documents |
| Trusted default removed, `Unique` left in memo | Decision `Scm`, no `Reparse`, no events |
| Mixed-case repository `https://github.com/Apple/Swift-NIO` | Host lowercased, path case kept; OSV name `github.com/Apple/Swift-NIO` |
| Registry indexes exact `…/x.git`, written URL has `.git` | Written URL sent; canonical retry only on `NotRegistered` |
| `branch:`/`revision:`/scp/ssh | Never eligible |
| Non-GitHub swizzled dependency | Registry versions; OSV and license not scannable via public content (default gate, `AlternateRegistry`), no new false vulnerability claims |
| Continuous typing during PreFetch | Lookups survive task abort; no re-send per keystroke |
| Several identifiers / invalid identity | SCM form (`Ambiguous`/`Rejected`) |

## 8. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | mockito: 200 unique, 200 several, 404, 5xx, invalid identity | Matching `IdentityLookup` and form |
| SC-002 | Trust gate | Workspace-declared default never queried; mock asserts zero hits |
| SC-003 | Credential test (NFR-001) | Mock never sees `TOKEN` |
| SC-004 | Convergence test (NFR-002) | Zero reparse/events over N cycles |
| SC-005 | Same OSV advisory before/after swizzle; license deny-list fires, tested end to end through the real tier-3 lookup and hover/diagnostic path (not a unit test of the license map in isolation) | Pass |
| SC-009 | Mixed-case repository path (`https://github.com/Apple/Swift-NIO`) | `public_content` name is `Apple/Swift-NIO` (case preserved); OSV query is `github.com/Apple/Swift-NIO` and the advisory matches (SwiftURL matching is case-sensitive) |
| SC-006 | Latest verdict after swizzle | `Unverified` until phase B commits |
| SC-007 | CLI vs LSP on the same fixtures | Identical output; incomplete-lookup stderr note |
| SC-008 | Live: user-tier default registry (or a local SE-0292 stub) with `Replace` | Registry versions shown for an eligible URL dependency |

## 9. Test Plan

mockito for identifiers (200 unique, 200 several, 404, 5xx, invalid identity, canonical retry); trust gate; config parse and diff (`PolicyConfigDiff` triggers reparse); branch/revision/scp/ssh never swizzled; `swizzle_decision` truth table; memo stale-while-revalidate, idle eviction, `Failed` non-overwrite, generation increments; detached lookup survives abort; conformance fixture for `public_content`; mixed-case repo; deny-list through the real license path keyed by `scope.name`; CLI order test (parse, PreFetch, one reparse, fetch, PostFetch). Update `.local/testing` (coverage, Swift playbook, regressions).

## 10. Agent Boundaries

**Always**: reuse 086 infrastructure and `redact`; keep enums exhaustive; CHANGELOG `### Added` one line with PR link; book `swift.md`.
**Ask first**: consulting any registry other than the trusted user-tier default; widening eligibility; adding lookups to `ProbeAllowance`.
**Never**: send userinfo/query/fragment; do network I/O in the parser; let a stale or `Failed` answer flip the form; use `dep.name()` for OSV naming of a swizzled dependency; edit `crates/deps-zed`.

## 11. Follow-ups

| ID | Title | Labels |
|----|-------|--------|
| F-4 | Swift registry-pin in-use matching: **not needed**, covered by the `id:` substitution (FR-018); file only if a live gap is found | none now |
| F-5 | Optional: auto-detect the Xcode default `IDEPackageDependencySCMToRegistryTransformation` (macOS only) | `enhancement`, `P4` |

## 12. See Also

[[MOC-specs]] · [[077-swift-registry-client/spec|077]] · [[084-unified-registry-trust-rule/spec|084]] · [[086-git-ref-probe-branch-evidence/spec|086]] · issue #1757 · [[plan]] · [[tasks]]

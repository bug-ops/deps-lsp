# Architecture Overview

This page is the deep-technical reference for how `deps-lsp` is put together — read
[Editor Setup](editor-setup.md), [Configuration](configuration.md), and the
[Ecosystem Reference](ecosystems/index.md) first if you're new here. Everything below assumes
you already know *what* the server does; this explains *how*.

Every ecosystem is a thin, independent implementation of a small set of shared abstractions
defined in `crates/deps-core`. The binary, `crates/deps-lsp`, wires ecosystem crates into a
running LSP server via `tower-lsp-server` and does not itself know anything ecosystem-specific:
parsing, registry access, and LSP response formatting are all delegated through the traits
described below, so `deps-lsp` itself is only a request-dispatch and document-lifecycle layer.

## The `Ecosystem` trait

`Ecosystem` (`crates/deps-core/src/ecosystem.rs`) is the extension point every ecosystem crate
implements — see `crates/deps-cargo/src/ecosystem.rs` for a concrete example. It is a sealed
trait (requires `Self: ecosystem::private::Sealed`), so it can only be implemented from inside
this workspace: `private::Sealed` lives in a `pub` (but `#[doc(hidden)]`) module, because Rust
has no visibility level meaning "this workspace's crates, but no others" — sealing here is a
documented contract enforced by code review, not a compiler-enforced wall.

### Identity and routing

- **`EcosystemId`** — an exhaustive, *not* `#[non_exhaustive]` enum of every supported
  ecosystem, generated from one variant list by the `ecosystem_ids!` macro (which also derives
  `EcosystemId::ALL`, `EcosystemId::id()`, and its `FromStr` impl, so the three can never drift
  apart). Any code that needs to *branch* on ecosystem identity should match on this enum
  instead of re-deriving a partial string match: an unhandled variant here is a compile error,
  while an unhandled string is a silent runtime bug (the class of bug issue #118 fixed, where
  two call sites silently mishandled ecosystems missing from an incomplete string match).
  Adding a 15th ecosystem therefore forces every exhaustive `match` on `EcosystemId` across the
  workspace — including `EcosystemId::osv_ecosystem()`'s OSV.dev name mapping and
  `deps-core::deps_dev`'s deps.dev `system` mapping — to be updated at compile time.
- **`ParseResult` / `Dependency`** — trait-object interfaces a parser returns; ecosystem-specific
  dependency types are exposed generically but remain downcastable via `as_any()`.
  `ParseResult::blocked_registries()` additionally reports any dependency line whose
  registry-index resolution was blocked by the workspace-registry reachability policy (see
  [Network security](#network-security-ssrf-host-classification) below), so a blocked custom
  registry never degrades silently — it renders an `INFORMATION`-severity diagnostic instead.
- **Manifest routing** is checked by `EcosystemRegistry` in a fixed four-stage order, each
  stage only consulted once the previous one misses:
  1. `manifest_filenames()` — exact basename match (`Cargo.toml`, `package.json`).
  2. `manifest_patterns()` — single-`*`-wildcard basename globs (`requirements*.txt`),
     case-sensitive.
  3. `manifest_extensions()` — file extension only, for basenames that vary
     (`.csproj`/`.fsproj`/`.vbproj` for NuGet's MSBuild project files).
  4. `manifest_directory_patterns()` — `(directory_path, suffix)` pairs matched against the
     *tail* of the file's directory path on segment boundaries (`.github/workflows/*.yml` for
     GitHub Actions, `requirements/*.txt` for PyPI's split-file layout) — the only stage that
     needs the full path, so it's reachable only from `EcosystemRegistry::for_uri`, never
     `for_filename`.

  A separate, single-purpose lookup, `EcosystemRegistry::for_lockfile`, matches an ecosystem's
  `lockfile_filenames()` (`Cargo.lock`, `package-lock.json`, ...) so file-watcher events on a
  lock file route to the right ecosystem for a resolved-version refresh without a full
  reparse. `for_watched_config` does the same for `watched_config_filenames()` — non-lockfile
  config an ecosystem resolves *during* parsing (npm's `pnpm-workspace.yaml`, `.npmrc`) — except
  a change there triggers a full document reparse, not just a cache refresh, since the config's
  value is baked into the parsed `ParseResult` rather than looked up separately.

### LSP response generation

`generate_hover` / `generate_diagnostics` / `generate_code_actions` / `generate_code_lenses` /
`generate_inlay_hints` all have default implementations delegating to shared logic in
`deps-core::lsp_helpers`, driven by the ecosystem's own `formatter()` (an `EcosystemFormatter`
implementation, see below) and `registry()` (a `Registry` implementation) — most ecosystem
crates only need to supply parsing plus a formatter and a registry client, not reimplement LSP
response generation. Override a `generate_*` method only for genuine ecosystem-specific
behavior.

`generate_completions` has **no default that every ecosystem inherits for free** in the way the
other `generate_*` methods do — the trait provides a default dispatch, but every ecosystem is
expected to reason about it explicitly. That default detects the
`deps_core::completion::CompletionContext` at the cursor position (`PackageName`, `Version`, or
`Feature`) and dispatches to one of three hooks:

- `complete_package_name` — usually built on `deps_core::completion::complete_package_names_generic`.
- `complete_version` — usually built on `deps_core::completion::complete_versions_at_position`,
  which also threads through `freshness.enabled` so version completion items can carry a
  relative-age label. `version_operator_chars()` tells this default which leading operators
  (npm's `^`/`~`, PyPI's `>=`/`!=`, NuGet's bracket intervals) to strip from a completion prefix
  before matching registry versions.
- `complete_feature` — feature-flag array entries; only Cargo and Go override this (most
  ecosystems have no feature-flag concept).

`deps-maven` and `deps-gradle` override `generate_completions` wholesale instead, because they
route on their own XML/Groovy-DSL cursor context rather than `CompletionContext`. When the
manifest fails to parse entirely (typically mid-edit), `deps-lsp` falls back to
`fallback_completion_prefix`/`completion_insert_text`/`fallback_bare_insert_text` — a raw-text,
parse-free completion path most ecosystems implement via the shared scanners in
`deps_core::fallback_completion`.

### `EcosystemConfig` and `LicenseSource`

`EcosystemConfig` (inlay-hint text/behavior — up-to-date/needs-update/loading text, offline
marker) and `LicenseSource` (`RegistryDeclaredSpdx` / `FetchedDeclaredSpdx` / `DetectedSpdx` /
`PomFreeText`, driving hover's "(detected)" qualifier and whether `fetch_license` needs a
dedicated call — see [Licensing](cross-ecosystem/licensing.md)) are both `#[non_exhaustive]`
structs/enums built via a `new()` + `with_*` builder chain rather than a struct literal, so
adding a field or variant never breaks an out-of-crate construction site.

## `Registry` and `EcosystemFormatter`

**`Registry`** (`deps-core::registry`) is the trait every ecosystem's registry client implements
for version lookup and search, type-erased behind `Arc<dyn Registry>` so `deps-core`'s generic
LSP-response code never needs to know the concrete registry type. Each ecosystem's own registry
struct (`CratesIoRegistry`, `NpmRegistry`, ...) *additionally* exposes the same operations as
concrete, unboxed **inherent** async methods, which ecosystem-internal code and conformance
tests call directly. The trait method of a given name is expected to delegate to its inherent
counterpart. The canonical method vocabulary (issue #834, enforced at compile time for 9 of 14
ecosystem crates via `registry_conformance!`) is:

| Method | Purpose |
|--------|---------|
| `get_versions` | Fetch all versions. |
| `get_versions_with` | Fetch all versions plus extra data (e.g. publish dates for freshness). |
| `get_latest_matching` | Fetch the single version matching a requirement. |
| `search` | Fetch search results for a query (package-name completion). |
| `register_alternate` | Register an alternate/private registry source. |
| `package_url` | Build the registry's web-display URL for a package. |
| `with_base` | Construct a client pointed at a non-default base URL (tests, alternate-registry hops). |

Four crates are documented exceptions rather than silent drift: `deps-gitlab-ci` has no
name+version registry concept at all (route-based); `deps-deno`'s `DenoRegistry` is a
scheme-dispatching facade over a `JsrRegistry` and an `NpmRegistry`, not one struct; `deps-go`
and `deps-github-actions` both lack `search` because neither ecosystem has a package-name search
concept a user would complete against.

**`EcosystemFormatter`** (`deps-core::lsp_helpers::formatter`) governs everything about how a
resolved package/version becomes LSP-response text, split into seven focused sub-traits an
ecosystem composes rather than one large interface:

| Sub-trait | Contract |
|-----------|----------|
| `PackageNaming` | Normalizes/validates a manifest-declared package name into a stable lookup key. |
| `PackageRendering` | Formats a version into manifest-safe text edits and builds the registry package URL. |
| `RequirementResolution` | Pure (no I/O) requirement parsing/matching and up-to-date status — the hot hover/diagnostic path. `requirement_is_unresolved`'s default delegates to `requirement_is_placeholder`, so an ecosystem with an unexpanded-placeholder syntax (Maven, Gradle, NuGet, Cargo, npm, ...) overrides only the latter to distinguish "not yet decidable" from "decided outdated." GitHub Actions and GitLab CI override `requirement_is_unresolved` directly instead, since their SHA/branch pins are undecidable-but-not-a-placeholder — a case the default doesn't cover. |
| `DiagnosticMessages` | Static, `'static` wording for yanked/deprecated diagnostics and hover — display copy only, cacheable across a whole diagnostics pass. |
| `DiagnosticPolicy` | Per-ecosystem opt-outs narrowing or disabling a diagnostic a shared pass would otherwise emit (e.g. npm disables the yanked-requirement diagnostic to avoid duplicating its package-deprecation diagnostic). |
| `SourcePolicy` | Whether a `DependencySource` (registry/git/path) can be resolved, and whether it counts as public-registry content for vulnerability scanning and cache-key trust. |
| `OsvNaming` | Bridges native package-name/version-string conventions to OSV.dev's own naming when they diverge. |

## `LockFileProvider`

An ecosystem that supports resolved (lock-file) versions implements `LockFileProvider`
(`deps-core::lockfile`) alongside `Ecosystem`, returned from `Ecosystem::lockfile_provider()`
(`None` for an ecosystem with no lock-file concept):

- `locate_lockfile(manifest_uri)` — searches ancestor directories (bounded depth) for the
  lock file, returning `None` if it doesn't exist or the workspace-root search fails.
- `parse_lockfile(path)` — reads and parses it into `ResolvedPackages`.

Every implementation shares `read_lockfile_content`/`read_and_parse_lockfile`, which bound the
read to `MAX_LOCKFILE_BYTES` (32 MiB — deliberately larger than the 10 MB manifest cap and the
small-config-file cap in `mtime_cache`, since a large npm monorepo `package-lock.json` can
legitimately exceed 8 MiB) via `fs_probe::read_to_string_capped`, and run the whole
stat-then-read-then-parse sequence on the blocking-thread pool (`tokio::task::spawn_blocking`)
rather than the calling tokio worker — every `parse_lockfile` call sits on the live LSP request
path, and a lock file is discovered by an unauthenticated ancestor walk over a possibly hostile
cloned repository, so nothing may assume it's small or well-formed before reading it in full.

## The `deps-lsp` document state machine

`crates/deps-lsp/src/document/` implements one state machine per open document, independent of
which ecosystem it belongs to.

**`DocumentState`** holds the raw content, the parsed `ParseResult`, and every piece of fetched
data layered on top of it: `cached_versions`, `vulnerabilities` (OSV scan outcomes), `outcomes`
(per-dependency classification), `licenses`, and `resolved_version_candidates`. Each dependency's
fetch progress is tracked by **`LoadingState`**: `Idle` (default) → `Loading` (fetch in flight) →
`Loaded` (data cached) or `Failed` (fetch failed, but a stale cached value may still be shown).

**`ServerState`** is the global, `Arc`-shared server state: every open document (keyed by URI),
the shared `HttpCache`, the lock-file cache, and background-task bookkeeping. Two independent
concurrency limits bound outbound registry traffic:

- `cache.max_concurrent_fetches` (config, default 20) bounds fetches *within* one document.
- `FETCH_PERMITS` (4, hardcoded) bounds how many *documents* fetch concurrently at once — an
  axis the config knob doesn't cover, shared by both the document-open and document-change
  paths so neither alone can fan out unbounded registry traffic across many simultaneously
  edited files.

**Lifecycle** (`document/lifecycle.rs`) provides unified `didOpen`/`didChange`/`didClose`
handlers built on the `Ecosystem` trait, eliminating what used to be per-ecosystem duplication.
A `didChange` is debounced by `DID_CHANGE_DEBOUNCE` (100ms) before triggering a re-fetch, so a
burst of keystrokes coalesces into one registry round-trip rather than one per keystroke.
`ColdStartLimiter` separately rate-limits *disk-load* cold starts (a document an editor restores
without an explicit `didOpen`, see `cold_start.rate_limit_ms` in
[Configuration](configuration.md)) per URI, to prevent a client that thrashes file loads from
overwhelming the server.

**Reparse** (`document/reparse.rs`) is the shared driver behind two distinct triggers that must
re-evaluate every currently open document, not just one: a watched **config file** change
(`.npmrc`, `gradle.properties`, ...) and a live **`workspace/didChangeConfiguration`** settings
reload. Both reuse the same version-guarded, sequential-await machinery `didChange` uses, and
both debounce a burst of rapid-fire notifications — `RECONFIGURE_DEBOUNCE` (250ms) coalesces a
settings-file save's several notifications into one reparse round, capped by `MAX_DEBOUNCE_WAIT`
(2s) so a continuously chattering client can never defer the reparse indefinitely while the new
policy has already taken effect elsewhere.

`deps-core::policy_config::PolicyConfig::diff` computes exactly which parts of a config reload
require a reparse at all (`ReparseScope`): most policy sections (diagnostic severities, license
policy) are read fresh on every diagnostics pull and need no reparse, but `registries`'s three
fields each scope a different set of ecosystems and do force one. This distinction is enforced
at compile time — `diff`'s destructuring of every section is exhaustive (no `..`), so a field
added to any policy section without an explicit reparse-impact decision fails to compile
(rustc E0027), and a CI grep step asserts no `..` ever creeps back in.

## LSP handler dispatch and declared capabilities

`crates/deps-lsp/src/handlers/` is a thin dispatch layer, one file per LSP capability
(`hover.rs`, `completion.rs`, `diagnostics.rs`, `code_actions.rs`, `code_lens.rs`,
`inlay_hints.rs`, `document_link.rs`) — each resolves the request's `Ecosystem` via
`EcosystemRegistry`, then calls that ecosystem's `generate_*` method against already-cached
`DocumentState`. Every handler method is non-blocking by design: heavy work (registry fetches)
is always spawned via `tokio::spawn` ahead of time and cached, never awaited inline inside a
handler — a large minified manifest is even parsed on the blocking-thread pool
(`ecosystem::parse_manifest_blocking`) rather than synchronously on the tokio worker handling
the request, so one slow parse can never stall every other in-flight LSP request sharing that
worker.

`server.rs`'s `server_capabilities()` declares exactly what the client should expect:

| Capability | Detail |
|------------|--------|
| Text sync | Full-document sync (`TextDocumentSyncKind::FULL`) |
| Completion | Trigger characters `"`, `=`, `.`; label details supported; no resolve step |
| Hover | Simple (always available) |
| Inlay hints | Enabled |
| Code actions | `Refactor` and `QuickFix` kinds |
| Code lens | Enabled, no resolve step |
| Document links | Enabled, no resolve step |
| Diagnostics | Pull model (`textDocument/diagnostic`), identifier `"deps"`, no inter-file dependencies, no workspace-wide pull |
| Execute command | `deps-lsp.updateAllOutdated`, `deps-lsp.pinAllToSha` |

## Caching architecture

**`HttpCache`** (`deps-core::cache`), shared server-lifetime by every ecosystem's registry
client, wraps outbound registry requests with RFC 7232 conditional-request validation
(`ETag`/`If-None-Match`, `Last-Modified`/`If-Modified-Since`) so unchanged registry data is
served from a bounded in-memory cache instead of re-fetched. Two independent caps bound memory
use under a long-running session: `MAX_CACHE_ENTRIES` (1000 entries) and a 64 MiB total-bytes
budget across every cached response body — a single response can be as large as 32 MiB
(`MAX_RESPONSE_BYTES`), so the entry cap alone doesn't bound worst-case memory. Eviction
(`cache_policy::evict_expired_then_oldest`) always tries TTL-expired entries first, falling back
to the single oldest entry by fetch time only if nothing has expired; a full cache evicts
`CACHE_EVICTION_PERCENTAGE` (10%) of its capacity at once rather than one entry at a time.

**`dependency_cap`** bounds how many dependencies one open document tracks at all:
`MAX_DEPENDENCIES_PER_DOCUMENT` (5000) — hardcoded, not a config option, mirroring the 10 MB
manifest-size cap's "security limit, not a preference" reasoning. It exists specifically against
a pathological manifest (issue #796's repro: a 6.92 MB `package.json` with 330,000 unique
dependencies drove peak RSS to 850 MB and would have fanned out roughly 480,000 registry
requests). When truncation happens, `ParseResult::dependency_cap_info()` reports `Some((kept,
total))` so `deps-lsp` can surface a truncation notice rather than silently dropping
dependencies.

**`pagination`** drives the paged-fetch loop shared by every registry with a `per_page=100`-style
REST API (GitHub tags for GitHub Actions/Swift, GitLab tags/releases): page 1 is always fetched
alone first (to learn whether more pages likely exist, via `page_has_more`), then any further
pages are fetched **concurrently in batches** rather than sequentially. Hitting the safety
ceiling before pagination naturally ends logs a warning naming the API and the resource being
paginated, so truncation is diagnosable rather than looking identical to "no more matches."

## OSV.dev vulnerability scanning

`OsvClient` (`deps-core::osv`) batches every open document's dependency versions against
[OSV.dev](https://osv.dev) and resolves matching advisories, layered with its own semantic
cache (separate from `HttpCache`'s transport-level cache) on `ServerState` so every document
benefits from the same query/record cache across the whole session. A scan never surfaces an
error to the caller — every failure mode degrades to a `Skipped` outcome (`QueryFailed` or
`Truncated`) rather than an absent one, so a transient OSV outage never silently hides real
findings from a previous, still-valid scan.

A scan runs in two phases:

1. **Phase A** (`OsvClient::scan`) — the primary scan over every dependency's current version,
   chunked into `/v1/querybatch` requests (FR-009 chunk size) and, for any chunk OSV itself
   truncates, recovered via bounded, concurrent individual `/v1/query` calls
   (`MAX_TRUNCATED_REQUERY_BUDGET`) rather than accepting a silently incomplete result.
2. **Phase B** (`OsvClient::check_candidates`) — a follow-up check on the specific version(s)
   about to be *recommended* as an update (only for dependencies phase A already flagged), so a
   hover/code-action suggestion never recommends a version that's itself vulnerable.

Both phases share resolution logic bounded by an overall wall-clock `timeout`, checked between
chunks rather than wrapping the whole scan in a single cancellation — so already-completed work
is never discarded on timeout, only whatever hadn't started yet degrades to `Skipped`. A record's
full detail (summary, fixed-in version, severity) is fetched via bounded-concurrency `GET
/v1/vulns/{id}` calls, capped to `MAX_ADVISORY_RECORDS` (50) full records fetched per dependency —
the input `DependencyVulnerabilities::recommended_fix`/fix-target verification compute over, so a
fix recommendation is never computed from only a handful of the advisories OSV reported. Rendering
(hover, diagnostics, `deps-cli`) truncates that further to `ADVISORY_DISPLAY_CAP` (5) via
`DependencyVulnerabilities::advisories_for_display`, worst-severity-first, plus a trailing "+N more
advisories" entry — the fetch and render bounds are deliberately independent constants, not one
shared cap, so widening the render cap can never silently affect which fix version gets
recommended (or vice versa). Severity classification (`osv::severity`) checks, in
order: a confirmed-malicious `MAL-*` id/alias (always wins, regardless of any graded signal on
the same record); `database_specific.severity`; `ecosystem_specific.severity`; an allowlisted
`informational` value (`"unmaintained"` only — see
[Informational Advisories](cross-ecosystem/yanked-and-vulnerabilities.md#informational-advisories-issue-1043));
else `Unknown`.

## Supply-chain trust signal (deps.dev)

`DepsDevClient` (`deps-core::deps_dev`) assembles the hover Scorecard/provenance line (see
[Supply-Chain Trust Signal](cross-ecosystem/yanked-and-vulnerabilities.md#supply-chain-trust-signal-issue-543))
from [deps.dev API v3](https://docs.deps.dev/api/v3/) via a two-call sequence: a version-level
call (provenance/attestation data, keyed by `(base, ecosystem, name, version)` to prevent a test
mock server's response ever serving a real-API cache hit) and a project-level call (the
Scorecard, keyed separately since it's a property of the linked repository, not any one
package version — several packages sharing one upstream project share one cached call). Each
call has its own short per-call timeout, deliberately shorter than the hover-side overall wait
budget, so one hung call can never by itself starve the other of any chance to return. A
successfully assembled signal (or a definitive 404, treated as an authoritative "no record," not
a transient fault) caches for 1 hour, matching deps.dev's own `cache-control` header; a network
error, timeout, 5xx, or malformed response caches for a much shorter error TTL so a transient
outage self-heals within a couple of minutes of hovering.

## Network security: SSRF host classification

`net_policy` (`deps-core::net_policy`) is the shared gate every ecosystem with a
user/workspace-configurable registry host (Cargo custom registries, npm `.npmrc`, PyPI custom
indexes, GitLab self-hosted instances, NuGet feeds) routes through before fetching from it.

**`HostClass`** classifies a URL's host from the URL string alone (no DNS resolution — see
below for why): `Loopback`, `LinkLocal`, `CloudMetadata` (the specific `169.254.169.254`/
`fd00:ec2::254` instance-metadata address and provider-documented metadata hostnames),
`PrivateV4` (RFC 1918), `Cgnat` (`100.64.0.0/10`), `UniqueLocalV6` (`fc00::/7`), `Unspecified`
(`0.0.0.0`/`::`), `InternalName` (a `.internal`/`.local`/`.home.arpa`-suffixed or single-label
hostname), or `Global` (everything else). Classification also unwraps IPv4-mapped
(`::ffff:a.b.c.d`) and NAT64 well-known-prefix (`64:ff9b::/96`) IPv6 addresses to their embedded
IPv4 form first, so a bypass can't be written by re-encoding the same address in either form.

**`WorkspaceRegistryAccess`** — the user-facing policy (`registries.workspace_registries` in
[Configuration](configuration.md)) — decides which classes a *workspace-declared* registry URL
(one found inside the opened workspace's own manifest/config, never a user's own
`$CARGO_HOME`-tier config) may resolve to: `Off` (block every workspace-declared index
outright — the only complete boundary), `PublicOnly` (default — allow only `HostClass::Global`,
blocking an IP literal in a metadata/RFC1918 range while still allowing a legitimate corporate
`https://index.mycorp.dev`, since a DNS name can't be classified as internal without resolving
it), or `All` (allow every class — the escape hatch for a workspace that legitimately points at
an RFC1918/loopback registry). This string-based host classification is deliberately
DNS-resolution-free (an attacker-controlled hostname that merely *resolves* to a blocked range
isn't caught by `classify_host` itself); the DNS-rebinding TOCTOU that would otherwise open is
closed separately, at actual connect time, by a `BlockedAddrResolver` wired into every HTTP
client, which classifies the address a hostname *actually resolved to* and fails closed on any
lookup error.

`is_trusted_prefix` additionally hardens `HttpCache`'s redirect-hop confinement: a registry
response redirecting to another URL is only followed when the target shares the *origin* (not
just a textually similar hostname — `artifacts.corp.evil.com` must never pass as a redirect
target for `artifacts.corp`) and lies at or under the original URL's path at a proper
path-segment boundary.

## Secret handling

Any credential that must never reach a log line or a panic message — `GITHUB_TOKEN`,
`GITLAB_TOKEN` — is wrapped in `Redacted<T>` (`deps-core::secret`): its `Debug`/`Display` output
is always `***`, and its backing memory is zeroized on drop. Exposing the real value requires
calling `expose_secret()` explicitly at the one call site that needs it (building the HTTP
`Authorization` header), so a credential can never leak through an incidentally-derived
`#[derive(Debug)]` on a struct that embeds it. When a credential needs to participate in an
`HttpCache` cache key (so an authenticated response is never served back for an unauthenticated
or differently-authenticated request), `auth_digest` computes a salted hash of the origin and
secret — salted with a per-process random value, so the digest can't be reconstructed offline
even if it were to appear in a log line.

## Release-freshness signal

`freshness` (`deps-core::freshness`) implements the release-cooldown window described in
[Configuration](configuration.md#configuration-reference) and applied uniformly across every
ecosystem: `PublishTime` (a `Copy` Unix-epoch-seconds timestamp), `is_within_cooldown` (an
*exclusive* bound — a version published exactly `cooldown_secs` ago is no longer "recent"), and
`format_relative_age` (coarse bucketing into `"X minutes/hours/days/weeks/months/years ago"`, no
calendar-aware date arithmetic needed since it operates on a plain duration).

## Cross-ecosystem consistency is a first-class design rule

A feature implemented for one ecosystem but not shared through `deps-core` — instead of
reimplemented per-crate — is treated as a bug class in this project. Concretely: JSON
position/AST parsing (`deps-core::json_ast`), non-string dependency-value guards
(`deps-core::json_helpers`), file-size-capped reads (`deps-core::fs_probe::read_to_string_capped`
— the single TOCTOU-safe read path), and ancestor-config-search depth
(`MAX_CONFIG_ANCESTOR_DEPTH`) are all centralized in `deps-core` specifically because the same
fix was independently needed in two or more ecosystem crates at some point. When adding logic
that touches more than one ecosystem crate, check `deps-core::json_ast`, `json_helpers`,
`fs_probe`, `pagination`, `git_ref`, and `lsp_helpers` first for an existing shared helper before
writing ecosystem-local code.

## Crate layout

Each ecosystem is implemented as a separate crate under `crates/deps-{ecosystem}/` with the
following structure:

```text
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

The [Adding a New Ecosystem](contributing/index.md) chapters walk through building one of these
crates from scratch, step by step.

## Project structure

```text
deps-lsp/
├── crates/
│   ├── deps-core/      # Shared traits, cache, generic handlers
│   ├── deps-cargo/     # Cargo.toml parser + crates.io registry
│   ├── deps-npm/       # package.json parser + npm registry
│   ├── deps-pypi/      # pyproject.toml/requirements.txt parser + PyPI registry
│   ├── deps-go/        # go.mod parser + proxy.golang.org
│   ├── deps-bundler/   # Gemfile parser + rubygems.org registry
│   ├── deps-dart/      # pubspec.yaml parser + pub.dev registry
│   ├── deps-maven/     # pom.xml parser + Maven Central registry
│   ├── deps-gradle/    # Gradle parser (Version Catalog, Kotlin/Groovy DSL)
│   ├── deps-swift/     # Package.swift parser + GitHub API registry
│   ├── deps-composer/  # composer.json parser + Packagist registry
│   ├── deps-nuget/     # .csproj/packages.config parser + NuGet V3 registry
│   ├── deps-deno/      # deno.json parser + JSR registry (npm: delegates to deps-npm)
│   ├── deps-github-actions/ # workflow YAML parser + GitHub tags API registry
│   ├── deps-gitlab-ci/ # .gitlab-ci.yml parser + GitLab tags/releases API registry
│   ├── deps-engine/    # Shared classification pipeline (see engine.md) used by deps-lsp/deps-cli
│   ├── deps-lsp/       # Main LSP server
│   ├── deps-cli/       # `deps-cli check` — CLI for CI/pre-commit/shell workflows
│   ├── github-action/  # Docker-based GitHub Action wrapping `deps-cli check --format sarif`
│   └── deps-zed/       # Zed extension (WASM, separate git submodule)
├── .config/            # nextest configuration
└── .github/            # CI/CD workflows
```

See [deps-engine](engine.md) for why the classification pipeline is its own crate rather
than living inside `deps-lsp`, and [deps-cli](cli.md) / [GitHub Action](github-action.md) for the
non-editor ways to run these checks.

## Performance

`deps-lsp` is optimized for responsiveness — parallel per-dependency fetching, aggressive
caching, and non-blocking handlers keep the interactive paths fast even on a manifest with
hundreds of dependencies:

| Operation | Latency | Notes |
| ----------- | --------- | ------- |
| Document open (50 deps) | ~150ms | Parallel registry fetching |
| Inlay hints | <100ms | Cached version lookups |
| Hover | <50ms | Pre-fetched metadata |
| Code actions | <50ms | No network calls |
| Code lens | <50ms | No network calls; in-memory only |

Lock file support provides instant resolved versions without network requests.

Run performance benchmarks with criterion:

```bash
cargo bench --workspace
```

View the HTML report at `target/criterion/report/index.html`.

## Versioning policy

`deps-core`'s public trait signatures (`Ecosystem`, `Dependency`, `ParseResult`,
`EcosystemFormatter`) — and its public `lsp_helpers` / `completion` helper functions — are typed
directly against `tower_lsp_server::ls_types` types. `tower-lsp-server` is pinned pre-1.0, so a
`tower-lsp-server` minor bump (e.g. 0.23 → 0.24) is not an implementation detail `deps-core` can
absorb silently — it forces a breaking release of `deps-core`: a minor version bump while
`deps-core` itself remains pre-1.0, a major version bump once `deps-core` reaches 1.0.

If you implement `Ecosystem` outside this workspace, depend on the exact matching
`tower-lsp-server` version via `deps_core::tower_lsp_server` rather than adding your own separate
direct dependency on `tower-lsp-server`, to avoid it drifting out of sync with the version
`deps-core` was built against.

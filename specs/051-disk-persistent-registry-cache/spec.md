---
aliases:
  - Disk-Persistent Registry Cache
  - HttpCache Disk Persistence
tags:
  - sdd
  - spec
  - research
  - caching
  - performance
created: 2026-09-09
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Disk-Persistent Registry Cache

> [!info] Metadata
> **Author**: continuous-improvement cycle (research finding)
> **Branch**: none yet — research spec, no implementation started
> **Priority**: P3 (research/parity)

## 1. Overview

### Problem Statement

`deps-lsp`'s registry response cache (`HttpCache` in `crates/deps-core/src/cache.rs`) is backed
entirely by an in-process `DashMap<String, CachedResponse>` (`cache.rs:739`), constructed empty
in every `HttpCache::new()` / `HttpCache::with_policy()` call. There is no disk-backed or
cross-process persistence layer anywhere in the workspace — confirmed by grepping `crates/` for
`sled`, `redb`, `rocksdb`, `sqlite`, and any `std::fs`-based cache-entry serialization, all of
which return zero hits outside of unrelated manifest/lockfile parsing code.

Consequently, **every LSP server process restart is a full cold start** for registry data:
editor reload or crash-recovery, machine reboot, an editor spawning a fresh `deps-lsp` process
when switching workspaces, or a bare `deps-lsp --stdio` invocation from CI tooling all discard
100% of previously-fetched crates.io / npm / PyPI / GitHub-tags / etc. responses, even for
dependency versions that have not changed since the previous session.

This has two concrete costs already acknowledged elsewhere in this project:

1. **GitHub API rate-limit exhaustion.** GitHub's unauthenticated REST API limit (60 req/hr) is
   called out repeatedly in this project's own specs (`[[031-github-actions-sha-pin-diagnostic/spec]]`,
   `[[039-github-rate-limit-actionable-diagnostic/spec]]`) and in `GithubTagsClient`'s ETag/304
   machinery. A cold-started server re-issues a full, unconditional request for every
   GitHub-sourced pin (GitHub Actions `uses:`, and prospectively pre-commit hooks per
   `[[044-precommit-hooks-ecosystem/spec]]`) before any 304 conditional-request savings can
   apply — there is nothing on disk yet to send `If-None-Match` against.
2. **No parity with CLI competitors.** Every mainstream CLI dependency tool in adjacent
   ecosystems (npm, cargo, pip) maintains a persistent on-disk cache across separate tool
   invocations. This specific angle — disk persistence — has never been evaluated in any of the
   52 prior continuous-improvement cycles (verified by grepping `.local/testing/journal/*.md`,
   `.local/testing/playbooks/*.md`, and `.local/testing/process-notes.md` for "disk persist",
   "in-memory only", "sled", "redb", "process restart", "editor restart" — no hits), even though
   `continuous-improvement.md`'s own Research & Innovation section lists "disk persistence" as
   one of three named caching-strategy research areas (alongside "TTL tuning" and "background
   refresh") and it appears to be the only one of the three never investigated.

The existing ETag/Last-Modified conditional-request support (`HttpCache`'s 304 handling,
`GithubTagsClient`) reduces *bandwidth* once a cache entry exists, but provides zero benefit to
request *count* against rate-limited APIs on a cold process start, since a conditional request
requires a prior cached representation to validate against.

### Goal

Determine whether, and how, previously-fetched registry responses that are still fresh under
`HttpCache`'s existing freshness/TTL semantics can survive an LSP server process restart, so that
a new server instance against the same or an overlapping workspace does not need to re-fetch
every dependency's registry data from zero — reducing both latency-to-first-response after
restart and GitHub rate-limit consumption in particular.

This is a **research spec**: its deliverable is a validated recommendation (adopt disk
persistence with a specific design, adopt a narrower variant, or explicitly decline), not a
committed implementation. Per the project's `research/parity, P3` classification, this spec
stops at `specify` — no `/sdd plan` is implied unless the recommendation is "adopt."

### Out of Scope

- Any actual disk-cache backend implementation (crate selection, schema, file format) —
  left to `/sdd plan` if this research spec's recommendation is "adopt."
- Changing `HttpCache`'s in-memory eviction policy (`MAX_CACHE_BYTES`, `MAX_CACHEABLE_ENTRY_BYTES`)
  or its ETag/304 conditional-request logic — a disk layer would sit alongside, not replace, that
  machinery.
- Cross-machine or team-shared cache synchronization (e.g. a shared network cache) — this spec
  considers only same-machine, same-user persistence across process restarts.
- Persisting anything other than registry HTTP responses already covered by `HttpCache` (no new
  caching of, e.g., parsed manifest ASTs or lockfile data).

## 2. User Stories

### US-001: Faster warm restart for GitHub-heavy workspaces
AS A developer whose workspace pins many `uses:` GitHub Actions references (or, prospectively,
pre-commit hook repos)
I WANT the LSP server to recognize on restart that it already has fresh, previously-fetched tag
data for those references
SO THAT reopening my editor does not burn through GitHub's 60 req/hr unauthenticated budget
before any hover/diagnostic can be shown, and does not silently degrade into rate-limit-driven
missing data.

**Acceptance criteria:**
```
GIVEN a workspace with N GitHub-sourced dependency pins, already resolved and cached
  from a prior server session within the last TTL window
WHEN the LSP server process is restarted and the same workspace is reopened
THEN the server SHALL NOT re-issue N unconditional GitHub API requests before serving
  the first hover/diagnostic for those pins
```

### US-002: No regression in correctness or staleness guarantees
AS A developer relying on hover/diagnostics to reflect current registry state
I WANT a restored-from-disk cache entry to be held to the exact same freshness rules as an
in-memory entry
SO THAT restarting my editor never causes deps-lsp to show me a version, vulnerability, or
license fact that is more stale than what the existing in-memory TTL/eviction policy would ever
allow.

**Acceptance criteria:**
```
GIVEN a disk-persisted cache entry whose age exceeds the freshness window that would evict or
  force-revalidate an equivalent in-memory entry
WHEN the entry is loaded back into a restarted server's HttpCache
THEN the server SHALL treat it as stale and behave identically to a cold cache-miss
  (fetch fresh, or 304-validate, per the existing conditional-request path) — never serve it
  as fresh
```

### US-003: Safe under two concurrently running server processes
AS A developer with two editor windows open on the same or overlapping workspace(s)
I WANT both `deps-lsp` processes to be able to read and write a shared on-disk cache without
corrupting it or crashing either process
SO THAT adopting disk persistence does not introduce a new class of multi-window bug.

**Acceptance criteria:**
```
GIVEN two `deps-lsp --stdio` processes running concurrently against overlapping workspaces
WHEN both processes read from and write to the same on-disk cache location at the same time
THEN neither process SHALL crash, hang, or observe a corrupted/partially-written cache entry
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN. Several requirements are intentionally left underspecified
pending the `[NEEDS CLARIFICATION]` items in §9 — this is expected for a research-phase spec.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN an `HttpCache` entry is written that satisfies the disk-persistence eligibility criteria (see FR-006) THE SYSTEM SHALL make that entry recoverable by a subsequent `HttpCache` constructed by a new process, without requiring a network request, provided it is still within its freshness window | must |
| FR-002 | WHEN `HttpCache::new()` (or its policy-carrying constructor) is called on process startup THE SYSTEM SHALL attempt to load any existing on-disk cache before serving the first registry request, without blocking LSP `initialize` handling beyond an acceptable startup-latency budget (see NFR-001) | must |
| FR-003 | WHEN a disk-loaded entry's age (however "age" is defined once `fetched_at`'s non-serializable `Instant` type is addressed — see §9) exceeds the same threshold that would force revalidation or eviction for an equivalent in-memory entry THE SYSTEM SHALL treat it identically — revalidate via the existing ETag/Last-Modified conditional-request path or refetch, never serve it as unconditionally fresh | must |
| FR-004 | WHEN the on-disk cache file/store is missing, unreadable, or fails to deserialize (corruption, format-version mismatch after an upgrade) THE SYSTEM SHALL fall back to an empty in-memory cache and continue operating exactly as it does today, without crashing or blocking startup | must |
| FR-005 | WHEN `HttpCache::set_offline(true)` is active THE SYSTEM SHALL still serve disk-persisted entries that satisfy the existing offline-fallback contract, consistent with how `Self::ensure_online`/`set_offline` already treat the in-memory cache | should |
| FR-006 | WHEN determining what to persist THE SYSTEM SHALL apply the same `MAX_CACHEABLE_ENTRY_BYTES` per-entry cap already enforced for in-memory storage, so a disk layer cannot become a bypass for the existing single-entry cap rationale | must |
| FR-007 | WHEN two `deps-lsp` processes concurrently persist to the same on-disk location THE SYSTEM SHALL NOT corrupt the store or cause either process to crash or hang (see US-003 and `[NEEDS CLARIFICATION: concurrent-process safety mechanism]`) | must |
| FR-008 | WHEN a namespaced cache-key tier exists in-memory (`CacheTier::WorkspaceDeclared`, `CacheTier::Pinned`, the `[[024-net-policy-dns-rebinding/spec]]`-driven workspace namespace) THE SYSTEM SHALL preserve the same tier/namespace separation on disk, so a policy tightening between sessions cannot cause a previously-looser-policy body to be served back (mirrors the existing in-memory guarantee documented on `HttpCache::cache_key`) | must |
| FR-009 | WHEN a secret-bearing cache entry exists (an authenticated registry response cached under `CacheTier::Pinned`, keyed in part by `auth_id`) THE SYSTEM SHALL NOT write the credential itself to disk, and SHALL apply at least the same redaction discipline `crate::secret::Redacted<T>` enforces in memory (see `[[041-credential-redaction-hardening/spec]]`, `[[045-secret-accessor-auditable-naming/spec]]`) | must |
| FR-010 | IF disk persistence is configurable (on/off) THEN THE SYSTEM SHALL expose that toggle through the same `parse_config`/`did_change_configuration` path `server.rs` already uses for all other config, not a separate, unvalidated path (see `[NEEDS CLARIFICATION: opt-in vs on-by-default]`) | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Loading the on-disk cache at startup SHALL NOT add more than a small, bounded delay to LSP `initialize`/first-request handling — target and measurement method TBD (see `[NEEDS CLARIFICATION: startup-load latency budget]`) |
| NFR-002 | Performance | The disk-persistence mechanism SHALL NOT measurably regress hover/completion latency for the already-cached, warm in-memory path (i.e., no synchronous disk I/O introduced onto a hot read path that is today served purely from `DashMap`) |
| NFR-003 | Reliability | A corrupted, truncated, or version-mismatched on-disk store SHALL degrade to an empty cache rather than causing a panic, hang, or `initialize` failure (mirrors FR-004) |
| NFR-004 | Security | On-disk cache contents SHALL be subject to the same trust boundary as any other local cache file: no secrets in plaintext beyond what FR-009 permits, and file permissions consistent with other state this project already writes to disk (age vault conventions are the closest existing precedent, though this is not itself a vault use case) |
| NFR-005 | Portability | The chosen persistence mechanism (crate, file format, directory convention) SHALL work across the same OS matrix CI already tests (`ubuntu`/`macos`/`windows` per `.github/workflows` test matrix) without platform-specific special-casing beyond directory-path resolution |
| NFR-006 | Maintainability | Any new dependency introduced for this SHALL be checked via context7 for current version per user workflow conventions, and SHALL comply with the workspace's `unsafe_code = "forbid"` lint and existing dependency policy (no `openssl-sys`, TLS via `rustls`, dependency versions pinned only in root `[workspace.dependencies]`) |

## 5. Data Model

No new domain entities — this is a persistence-layer question for an existing entity.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CachedResponse` (existing, `cache.rs:683`) | A single cached registry HTTP response, currently held only in `HttpCache::entries: DashMap<String, CachedResponse>` | `body: Bytes`, `etag: Option<String>`, `last_modified: Option<String>`, `fetched_at: Instant` — note `Instant` is process-relative monotonic time and has no cross-process meaning; any disk representation needs a wall-clock-derived substitute or reinterpretation of "freshness age," which is unresolved (see §9) |
| Disk cache store (proposed, not yet designed) | On-disk representation of a subset of `entries`, keyed identically to the in-memory `cache_key()` scheme (including tier/namespace prefixes per FR-008) | Backend, file format, and location are all `[NEEDS CLARIFICATION]` (see §9) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| On-disk store does not exist yet (first run ever) | Behaves exactly as today: empty cache, normal cold-start fetches |
| On-disk store exists but is from an incompatible/older schema version | Treated as unreadable — fall back to empty cache (FR-004), never attempt partial/best-effort parsing that could silently misinterpret bytes |
| On-disk store exists but an entry's body exceeds `MAX_CACHEABLE_ENTRY_BYTES` (e.g. written by a future version with a larger cap) | That entry is skipped/discarded on load, not truncated or partially loaded |
| Disk write fails mid-flight (disk full, permissions revoked, sandboxed/read-only environment) | In-memory cache continues operating unaffected; the failure is logged (`tracing`, per project convention) but never surfaced as a user-facing LSP error |
| Two `deps-lsp` processes race to write the same key at the same time | No corruption; last-writer-wins is acceptable as long as neither process observes a torn/partial read (see FR-007 and `[NEEDS CLARIFICATION]`) |
| Workspace-registry policy (`RegistryAccessPolicy`) is tighter in the new session than when an entry was written under a looser policy | The tier/namespace separation already required by FR-008 must prevent the looser-policy body from ever being served under the new, tighter tier — identical to the existing in-memory guarantee |
| `HttpCache::set_offline(true)` is active at startup, before any disk-cache load completes | Load must not require network access — this is a pure local-disk read, so it should be safe to run regardless of offline mode; must not deadlock with `ensure_online`/`cache_enabled` initialization ordering |
| Disk cache grows unbounded over many sessions (packages that are queried once and never again) | Needs an eviction/pruning strategy analogous to `MAX_CACHE_BYTES` for the in-memory map — currently `[NEEDS CLARIFICATION]` |

## 7. Success Criteria

Measurable metrics that would validate an "adopt" recommendation, to be confirmed empirically
(per this project's live-testing principle — no conclusion from code reading alone) before any
implementation ships:

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | GitHub API requests issued in the first 60 seconds after a warm restart, for a workspace with ≥10 GitHub-sourced pins previously cached and still fresh | Reduced relative to today's cold-start baseline (baseline to be measured as part of validating this spec; exact reduction target TBD) |
| SC-002 | Time-to-first-hover-response after server restart for a workspace with a populated, fresh on-disk cache | No worse than the current cold-start time-to-first-hover, and measurably better once disk-load path is implemented |
| SC-003 | Staleness regression rate | Zero observed cases, under adversarial testing per this project's regression-testing conventions, of a disk-restored entry being served as fresher than the in-memory TTL/eviction policy would allow |
| SC-004 | Crash/corruption rate under concurrent dual-process access | Zero observed crashes or corrupted-store states across repeated concurrent-restart test scenarios |

## 8. Agent Boundaries

### Always (without asking)
- Verify every claim in this spec empirically before treating it as settled, per
  `continuous-improvement.md`'s live-testing principle — this spec documents a code-reading-based
  finding and explicitly has not yet been live-tested
- Follow existing code patterns (`HttpCache`'s tiering, `Redacted<T>` secret handling, `tracing`
  logging) if and when this moves to `/sdd plan`

### Ask First
- Adding any new dependency (disk-cache backend crate) — check current versions via context7 per
  user workflow conventions, and confirm it doesn't conflict with `unsafe_code = "forbid"` or the
  project's YAML/JSON tooling conventions
- Any change to the existing in-memory `HttpCache` eviction/TTL semantics, even if motivated by
  making disk persistence simpler

### Never
- Persist secrets (auth tokens, credentials) to disk in a form that regresses the redaction
  guarantees established in `[[041-credential-redaction-hardening/spec]]` and
  `[[045-secret-accessor-auditable-naming/spec]]`
- Implement this without first resolving the `Instant`-vs-wall-clock freshness question in §9 —
  doing so silently risks either always-stale (never trusted) or incorrectly-fresh (staleness bug)
  disk entries
- Move directly to `/sdd plan`/implementation without closing the open clarification items below,
  per this being a `research/parity` spec

## 9. Open Questions

- [NEEDS CLARIFICATION: disk cache backend/crate choice — a simple flat-file/JSON-per-key store under a cache directory, an embedded KV store (e.g. `redb`, `sled` — note neither appears in the workspace today and both would need dependency justification per the project's Simplicity principle), or SQLite via an existing workspace-approved crate. No decision has been made or researched in depth; this needs its own research pass weighing binary size, `unsafe_code = "forbid"` compatibility (some embedded-KV crates use `unsafe` internally), and cross-platform behavior]
- [NEEDS CLARIFICATION: cache directory location convention — platform cache dir via the `dirs`/`directories` crate (not currently a dependency), a `.deps-lsp/` folder under the workspace root (raises the question of whether it should be gitignored, and whether a per-workspace cache is even desirable vs. a single global one), or reuse of an existing app-data convention already established elsewhere in this project (none found)]
- [NEEDS CLARIFICATION: `fetched_at: Instant` is process-relative monotonic time with no meaning across a restart — resolving this requires either (a) adding a parallel wall-clock (`SystemTime`) field solely for disk serialization while keeping `Instant` for in-process comparisons, or (b) redefining "age" for disk-loaded entries in terms of a stored TTL-expiry wall-clock timestamp computed at write time. This is a prerequisite design decision, not a detail — FR-003 cannot be implemented without it]
- [NEEDS CLARIFICATION: invalidation/eviction interaction with `MAX_CACHE_BYTES`/`MAX_CACHEABLE_ENTRY_BYTES` — should the on-disk store have its own independent byte budget (likely larger, since disk is cheaper than RAM), and what evicts it (LRU on write? a periodic sweep? no eviction at all, relying on OS-level cache-directory conventions like XDG cache cleanup)?]
- [NEEDS CLARIFICATION: opt-in via config vs. on-by-default — given this is new, previously-unvalidated behavior touching every registry client, should it ship behind a config flag (`did_change_configuration`-driven, per FR-010) for at least one release before being on-by-default, or is the risk low enough (given FR-004's fail-open fallback) to enable immediately?]
- [NEEDS CLARIFICATION: concurrent-process safety mechanism — file locking (`flock`/advisory locks, noting the `rust-modern-apis` skill's mention of stable advisory file locking as a candidate), an embedded KV store's own MVCC/transaction guarantees, or a simpler last-writer-wins-per-key design relying on atomic file rename? This determines FR-007's actual implementation and needs to be validated with a real concurrent-dual-process test, not just reasoned about]
- [NEEDS CLARIFICATION: which cache tiers are eligible for disk persistence at all — should `CacheTier::Pinned` (authenticated) entries be persisted to disk at all, even redacted, given the generally higher sensitivity of anything touched by an auth path, or should FR-009's scope be simplified by excluding `Pinned` from disk persistence entirely in a first iteration?]
- [NEEDS CLARIFICATION: relationship to the `test-util` feature's loopback-relaxation and to `deps-lsp`'s non-dev dependency-tree guard — does a disk-cache crate need dev-only test scaffolding analogous to `test-util`, and does it risk widening the `cargo tree -p deps-lsp -e features,no-dev` guard surface?]
- [NEEDS CLARIFICATION: has this specific gap (disk persistence, as distinct from TTL tuning and background refresh) actually been evaluated by any competitor tool surveyed in `.local/testing/playbooks/competitive-parity.md` (Dependi, crates.nvim, Version Lens)? The finding's evidence notes these were "not checked specifically for disk persistence" — closing this requires a dedicated research pass via `/sdd`'s `rust-researcher`/`research-protocol` before any implementation priority is assigned]

## 10. See Also

- [[constitution]] — project principles (not yet created for this project)
- [[MOC-specs]] — all specifications
- [[031-github-actions-sha-pin-diagnostic/spec]] — establishes the GitHub rate-limit concern this spec responds to
- [[039-github-rate-limit-actionable-diagnostic/spec]] — actionable rate-limit diagnostics, closely related motivation
- [[037-supply-chain-trust-signal/spec]] — another `deps.dev`/OSV-adjacent client whose responses would also be disk-cache candidates
- [[041-credential-redaction-hardening/spec]] and [[045-secret-accessor-auditable-naming/spec]] — secret-handling constraints FR-009 must respect
- [[024-net-policy-dns-rebinding/spec]] — origin of the tier/namespace separation FR-008 must preserve
- [[044-precommit-hooks-ecosystem/spec]] — a prospective future GitHub-sourced ecosystem that would compound the rate-limit motivation in §1
- `crates/deps-core/src/cache.rs` — `HttpCache`, `CachedResponse`, `CacheTier` (source of truth for all in-memory behavior this spec extends)
- `.claude/rules/continuous-improvement.md` — Research & Innovation section listing "disk persistence" as an in-scope caching-strategy research area

---
aliases:
  - Disk-Persistent Registry Cache
  - HttpCache Disk Persistence
tags:
  - sdd
  - spec
  - enhancement
  - caching
  - performance
created: 2026-09-09
status: draft
related:
  - "[[plan]]"
  - "[[tasks]]"
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Disk-Persistent Registry Cache

> [!info] Metadata
> **Author**: continuous-improvement cycle (research finding), decisions finalized with the team lead
> **Branch**: `feat/700-disk-persisted-registry-cache`
> **Issue**: #700
> **Priority**: P4 (enhancement)
> **Phase**: plan and tasks written, zero open clarification items

> [!abstract] Decisions fixed by the user (not re-litigated here)
> - **R2 freshness**: a restored entry is served without a request for 10 minutes after its last validation (a 200 or a 304, restamped on 304).
> - **Enabled by default** and disableable: `cache.persistence = "disk"` (default) or `"memory"` (no disk I/O at all); deps-cli flag `--cache-persistence`; the GitHub Action is pinned to `memory`.
> - **Delivery** as 3 stacked PRs opened together and merged back to back (PR-A primitives, PR-B `HttpCache` wiring with production still `memory`, PR-C default-on flip with docs and the only `Closes #700`).

## 1. Overview

### Problem Statement

`HttpCache` (`crates/deps-core/src/cache/`) is backed only by an in-process `DashMap<String, CachedResponse>`. Every server or CLI process start is a full cold start for registry data: editor reload, crash recovery, reboot, a fresh `deps-lsp` per workspace, and every `deps-cli check` run (CI, pre-commit) discard 100% of previously fetched crates.io, npm, PyPI, GitHub-tags and other responses.

Two costs follow:

1. **GitHub API quota.** The unauthenticated REST limit is 60 requests per hour (see [[031-github-actions-sha-pin-diagnostic/spec]], [[039-github-rate-limit-actionable-diagnostic/spec]]). A cold process re-issues a request for every GitHub-sourced pin (GitHub Actions `uses:`, pre-commit hooks per [[044-precommit-hooks-ecosystem/spec]]) because there is nothing to validate against.
2. **No parity with CLI competitors**, which keep a persistent on-disk cache across invocations.

> [!warning] Corrections to the original research premise
> - `HttpCache` has **no TTL**. Every online hit sends a conditional request (`cache/fetch.rs`); only offline mode serves without one. "Freshness window" in this spec is therefore new behavior, scoped to restored entries only.
> - An **anonymous GitHub 304 spends quota**. Confirmed live by the critic (`/rate_limit` `core.used` went 1, 2, 3 for one 200 and two 304 responses); the REST docs grant the 304 exemption only to correctly authorized requests. Persisting entries alone (always revalidating) would save bandwidth but zero requests, which is why R2 was chosen.

### Goal

Previously fetched public-registry responses survive a process restart, and a restored entry is served without any network request for up to 10 minutes after its last validation, so a restart (or a repeated `deps-cli` run) inside that window sends no registry request for it.

### Out of Scope

- A configurable window, cache path or budgets (constants only; each needs user approval to change).
- An in-process anonymous revalidation throttle (a separate spec if wanted; critic Q2).
- Persisting GHES, self-hosted GitLab, operator- or workspace-declared registries, credentialed requests, `Pinned` entries, or search endpoints.
- Cross-machine or shared-network cache; same-user, same-machine only.
- Changing the in-memory eviction policy (`MAX_CACHE_BYTES`, `MAX_CACHEABLE_ENTRY_BYTES`) or the conditional-request logic.
- Persisting anything other than `HttpCache` responses (no parsed ASTs, no lockfile data, no per-ecosystem memo layers such as `RELEASE_DATES_TTL`).
- A `getpwuid` fallback when `HOME` is unset (the result is memory).

## 2. User Stories

### US-001: Warm restart sends no registry requests
AS A developer whose workspace pins many `uses:` GitHub Actions references (or pre-commit hook repos), or who re-runs `deps-cli check` repeatedly
I WANT the process to recognize that it already holds recently validated registry data
SO THAT reopening the editor or re-running the CLI does not spend GitHub's 60 req/hr anonymous budget.

**Acceptance criteria:**
```
GIVEN a workspace with at least 10 GitHub-sourced pins validated by a previous
  deps-lsp or deps-cli process less than 10 minutes ago
WHEN a new process starts and opens the same workspace
THEN it SHALL send 0 GitHub API requests for those pins until the 10-minute window
  since their last validation elapses (checked by /rate_limit core.used unchanged)
```

### US-002: Bounded staleness *(restated, approved change)*
AS A developer relying on hover and diagnostics
I WANT a restored entry to be never older than a fixed, small bound
SO THAT a restart never shows a version or tag fact staler than 10 minutes past its last validation.

> [!important] Approved change (R2), with the reason
> **Original**: "a restored entry is held to the exact same freshness rules as an in-memory entry" (always revalidate). **Now**: a restored entry may be served with no request for up to `RESTORED_FRESHNESS_WINDOW` (10 min) after its last successful validation by any process; after that it takes today's conditional-request path. Entries fetched in the current process keep today's revalidate-every-time behavior.
> **Reason**: an anonymous GitHub 304 spends quota (confirmed live), so always-revalidate meets neither goal of #700. Accepted trade-off: after a restart a release or yank can be invisible for up to 10 minutes, the same staleness an idle editor already shows; `cache.persistence = "memory"` is the workaround.

**Acceptance criteria:**
```
GIVEN a restored entry whose last validation is 10 minutes or older
WHEN it is read
THEN it SHALL take the existing conditional-request path (never served as fresh online)

GIVEN a restored entry whose last validation is under 10 minutes ago
WHEN it is read online
THEN it SHALL be served with no request
```

### US-003: Safe with concurrent processes
AS A developer with two editor windows (or an editor plus `deps-cli`) open
I WANT all processes to share the on-disk cache safely
SO THAT persistence introduces no multi-window bug.

**Acceptance criteria:**
```
GIVEN two processes reading and writing the same keys concurrently
WHEN each performs N reads and writes
THEN neither crashes or hangs and zero torn or corrupt entries are observed
```

### US-004: Safe default for every user
AS A user who never configured anything
I WANT persistence to be on and to degrade silently to memory when the directory is unusable
SO THAT it never breaks startup, never creates files owned by another user, and is easy to turn off.

**Acceptance criteria:**
```
GIVEN no initializationOptions and a writable owned cache root
WHEN the server starts and an eligible response is fetched
THEN the response is persisted under the OS cache directory

GIVEN cache.persistence = "memory"
WHEN any fetch occurs
THEN no cache directory is created and no disk read or write happens
```

## 3. Functional Requirements

### FR-001

WHEN an `HttpCache` stores a 200 response for an eligible key THE SYSTEM SHALL make it recoverable by a later process, where eligible means tier `Baseline`, `KeyAuth::Anonymous(None)`, https, no userinfo or fragment, a default-port domain host in the closed `PersistableHost` set, and only query keys from the closed `PersistableQueryKey` set (`page`, `per_page`, `order_by`, `sort`) with values matching `[A-Za-z0-9_.-]{1,32}` and no duplicate keys; a URL with a `page` key is eligible only when its caller declares a `PageRole` (see [[spec#FR-013]]).

**Priority**: must

### FR-002

WHEN the first eligible read or write occurs in a process THE SYSTEM SHALL open the disk tier lazily on a background blocking task (never at construction, never during `initialize`), and WHILE the tier is `Opening` a read SHALL await the transition bounded by the 250 ms read timeout, treating a timeout as a miss that does not degrade the tier, and writes SHALL be dropped.

**Priority**: must

### FR-003

WHEN a restored entry is read THE SYSTEM SHALL classify it by age since last validation (file mtime) as `Fresh` (0 <= age < 10 min: served with no request, online and offline), `Revalidate` (10 min <= age < 7 days, or an mtime 0 < skew <= 60 s in the future, which tolerates coarse mtime granularity and small clock skew: existing conditional path online, served offline, file kept), `Expired` (age >= 7 days: file deleted, miss) or `FromFuture` (mtime more than 60 s ahead of now: file deleted, miss), and a restored entry SHALL never be classified `Fresh` because the wall clock moved backward.

**Priority**: must

### FR-004

WHEN a cache file is missing, unreadable, truncated, fails its checksum, has a foreign magic or format version, or its URL or `Accept` does not equal the request THE SYSTEM SHALL treat it as a miss (deleting a corrupt file) and continue exactly as without persistence, without panic, hang or startup failure.

**Priority**: must

### FR-005

WHEN `HttpCache` is offline THE SYSTEM SHALL serve restored entries in classes `Fresh` and `Revalidate` without any network call, consistent with the in-memory offline contract.

**Priority**: should

### FR-006

WHEN persisting or loading THE SYSTEM SHALL apply `MAX_CACHEABLE_ENTRY_BYTES` (8 MiB) per entry and a 64 KiB header cap, skipping (never truncating) oversize entries.

**Priority**: must

### FR-007

WHEN two or more processes write the same key THE SYSTEM SHALL rely on per-key atomic rename (temp file in the same directory, owner-only mode) with no lock file, so a reader never observes a torn file.

**Priority**: must

### FR-008

WHEN deciding persistence THE SYSTEM SHALL persist `CacheTier::Baseline` entries only; `WorkspaceDeclared` and `Pinned` (policy-era, origin-pinned tiers) SHALL never reach disk, preserving the in-memory tier separation by exclusion.

**Priority**: must

### FR-009

WHEN a request carries a credential, a partitioned key or any header other than `Accept` THE SYSTEM SHALL NOT persist it; no token, digest or credential header SHALL be written to disk.

**Priority**: must

### FR-010

THE SYSTEM SHALL expose `cache.persistence` as a typed `CachePersistence { Memory, Disk }` enum (lowercase serde, unknown variants rejected, default `Disk`) through the existing `parse_config` and `did_change_configuration` path, applied live (`memory` stops reads and writes at once; files stay), plus a deps-cli flag `--cache-persistence <memory|disk>` on `check` and `update` that overrides config, and the GitHub Action entrypoint SHALL pass `--cache-persistence memory`.

**Priority**: must

> [!important] Approved change to FR-010
> **Original**: opt-in toggle. **Now**: enabled by default, `memory` disables. Approved by the user (default-on decision).

### FR-011

WHEN `ServerState::from_env_source(source)` is constructed THE SYSTEM SHALL resolve `PersistenceTarget::from_config(CachePersistence::default(), source)` once, from `source` only, and apply it to the cache, so default-on holds for clients that send no `initializationOptions`; `apply_resolved_config` SHALL only toggle between `Memory` and the resolved directory and SHALL never read the environment.

**Priority**: must

### FR-012

WHEN persisting a put or a 304 restamp THE SYSTEM SHALL carry the op's `validated_at`, drop an op older than the file's mtime, restamp (set mtime) only through one handle that also verified the header fingerprint (`etag`, `last_modified`, `accept`, `body_len`, `body_fnv1a64`) of the entry that was validated, and otherwise write the full entry with mtime equal to `validated_at`; keys known to be older on disk (`stale_on_disk`) SHALL always enqueue a full put and SHALL NOT be read through.

**Priority**: must

### FR-013

WHEN a restored entry has a `page` greater than 1 and was stored with the caller-declared role `PageRole::ListingPage` THE SYSTEM SHALL classify it `Fresh` only if its page-1 sibling is in memory as a `Fresh` restored entry and its own `validated_at` is at or after the page-1 `validated_at`, otherwise `Revalidate`; entries declared `PageRole::Standalone` (for example the compare probe `?per_page=1&page=2`) SHALL be classified by their own age only, and a URL with a `page` key and no declared role SHALL NOT be persisted.

**Priority**: must

### FR-014

WHEN opening the cache directory on Unix THE SYSTEM SHALL: obtain the probe uid from a `create_new` 0600 file in `std::env::temp_dir()`; require an existing root to be a directory owned by that uid (no mode requirement); create a missing root with a single non-recursive `create_dir` 0700 only when its parent is `$HOME` and `$HOME` is owned by that uid; create `deps-lsp/`, `http/`, `v1/` with mode 0700 and verify each (directory, not symlink, owned by the probe uid, no group or other bits); and on every entry read verify through the same handle a regular file owned by the probe uid with no group or other write bit, opened with `O_NOFOLLOW | O_NONBLOCK`; any failure SHALL yield `Memory` (or a miss for a file) without creating anything foreign-owned. macOS `~/Library/Caches` and Windows `%LOCALAPPDATA%` SHALL never be created. The root is `$XDG_CACHE_HOME` (absolute) or `$HOME/.cache` on Linux and other Unix, `$HOME/Library/Caches` on macOS (`XDG_CACHE_HOME` is **not** honored on macOS), and `%LOCALAPPDATA%` on Windows. WHEN opening the cache directory on Windows THE SYSTEM SHALL require the root to be an existing directory (never created), create `deps-lsp/`, `http/`, `v1/` ignoring `AlreadyExists`, and verify each is a directory and not a reparse point; uid, owner and mode checks are skipped per NFR-004.

**Priority**: must

### FR-015

WHEN the cache directory cannot be resolved or used (no `HOME`, read-only filesystem, insecure or foreign directory, probe failure), the first disk read exceeds the 250 ms read timeout, or 8 consecutive persistent write failures occur (`StorageFull`, `QuotaExceeded`, `ReadOnlyFilesystem`; `PermissionDenied` and Windows sharing violations are transient and never counted) THE SYSTEM SHALL fall back to `Memory` for the session with at most one `tracing::warn!` per process and target naming path and reason, report nothing over LSP, and leave deps-cli exit codes and output unchanged; the first successful use SHALL log one `info!` naming the directory.

**Priority**: must

### FR-016

THE SYSTEM SHALL bound the store at 64 MiB and 2048 files total, prune least recently validated first (mtime order, scan capped at 16384 directory entries, stale `*.tmp` older than 1 hour removed), bound the write queue at 256 ops and 16 MiB (drop when full, never block), and bound concurrent blocking reads with a semaphore of 8 permits, where a permit-wait timeout counts as a miss and never degrades the tier.

**Priority**: must

### FR-017

WHEN the LSP `shutdown` request is handled or a deps-cli command is about to exit THE SYSTEM SHALL call `flush_persistence` bounded at 2 s and never error.

**Priority**: should

### FR-018

THE SYSTEM SHALL keep `HttpCache::new()` and `HttpCache::with_policy()` at `PersistenceTarget::Memory`; only the adapters (deps-lsp `ServerState`, deps-cli runtime handles) select the product default, so libraries, benches and existing unit tests never touch a real directory.

**Priority**: must

## 4. Non-Functional Requirements

### NFR-001

Startup SHALL perform no disk I/O on the caller; a read waits at most the 250 ms read timeout; the open never counts against a read timeout and `Unavailable` is terminal. Testable: after `set_persistence(Disk(tmp))` the directory stays absent and empty until the first eligible read or write, and a `ServerState` built from a fake env creates nothing at construction (T008, T011, T015).

### NFR-002

Hot path: an in-memory hit SHALL perform no disk I/O; disk reads occur only on an in-memory miss for an eligible key, on `spawn_blocking`. Testable: a `#[cfg(test)]` disk-access counter stays at 0 across repeated in-memory hits, including after the directory is made unreadable (T008).

### NFR-003

Corrupt, truncated or version-mismatched data SHALL degrade to a miss; a future `v2` format SHALL never delete `v1` (an older binary may still use it).

### NFR-004

Security (Unix): directories 0700 and files 0600 (`FileMode::OwnerOnly` never copies the target's mode; deps-cli `update` keeps `PreserveTarget`); every component and every file is owner-checked; the root requires ownership only, because a group- or other-writable root can at most delete our directory (memory), never forge an entry, so umask-002 homes keep working. Windows relies on the per-user ACL of `%LOCALAPPDATA%` (uid and owner check skipped, documented; each store component is verified as a directory and not a reparse point; owner/DACL verification: follow-up #2146). `body_fnv1a64` is an integrity check, not an authenticity check.

> [!question] Open
> [NEEDS CLARIFICATION: the "at most delete our own directory" claim for a group- or other-writable root does not hold after `open`: such a root allows a symlink swap of a path component, so a later write batch or prune pass could act outside our directory. PR-B re-verifies the component chain before each prune pass and write batch (see T009), but does the user approve changing this wording and the root-ownership-only rule?]

### NFR-005

Portability: the same OS matrix as CI (ubuntu, macos, windows, i686, musl and win-arm64 cross targets); std-only filesystem code, no new C dependency; `u64` length and time fields go through `try_from`.

### NFR-006

Maintainability: no new dependency; `unsafe_code = "forbid"`; typed `thiserror` errors; exhaustive enums without catch-all arms; private constants `RESTORED_FRESHNESS_WINDOW` (10 min) and `MAX_PERSISTED_AGE` (7 days).

### NFR-007

CI guard: the ubuntu `test` job SHALL run nextest with `XDG_CACHE_HOME` set to a directory created by `mkdir -m 700 -p` (otherwise the guard is vacuous) and then assert `test ! -e "$XDG_CACHE_HOME/deps-lsp"`. macOS and Windows have no guard (documented).

### NFR-008

Privacy: the public package names a user looked up stay in the OS cache directory for up to 7 days; the README and book SHALL state this and how to disable it.

### NFR-009

Dependency-tree guard: no new `test-util` surface; test admission of loopback hosts is `#[cfg(test)]` inside deps-core only, and the `persistence_target()` test accessor is `#[cfg(feature = "test-util")] #[doc(hidden)] pub`, so `cargo tree -p deps-lsp -e features,no-dev` is unchanged.

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CachedResponse` (existing, `#[non_exhaustive]`) | In-memory cached response | gains a private `origin: EntryOrigin` (`Network` or `Restored { validated_at }`) |
| Cache entry file | One file per key, `<fnv1a64(url) hex>.entry` under `<cache>/deps-lsp/http/v1/` | magic, format version, JSON header (url, accept, etag, last_modified, link, body_len, body_fnv1a64), body; **mtime = last validation time** |
| `PersistKey` | Typed eligibility proof for a key | URL, `PersistableHost`, typed query keys, `Option<PageNumber>`, `PageRole`, accept |
| `PersistenceTarget` | Where an `HttpCache` persists | `Memory` or `Disk(CacheDir)` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| First run, no directory | Nothing happens until the first eligible response; then the directory is created (FR-014) and one `info!` is logged |
| `HOME` unset (container, CI, Nix sandbox) | `Memory`, one warn, no panic |
| `sudo` with preserved `HOME`, `sudo -E`, root container with mounted home | Root or home not owned by the probe uid: `Memory`; nothing foreign-owned is ever created |
| Root owned by another uid, or file planted with foreign ownership | `Memory` or a discarded miss |
| FIFO planted at an entry name | `O_NONBLOCK` open, `is_file` check on the handle, discarded |
| Version released less than 10 min before restart | May be invisible for up to 10 min; documented, `memory` disables |
| New tag inserted at the front; page 1 refetched, page 2 fetch fails | Page 2 (older stamp) revalidates after restart, so no existing tag is dropped (FR-013) |
| Standalone compare probe `?per_page=1&page=2` | Served `Fresh` from its own age; no page-1 anchor needed |
| A put was dropped (queue full) so disk holds an older body than memory | 304 for the newer entry writes the full entry, never restamps the older file (FR-012) |
| Older op arrives after a later validation | Dropped (mtime later than `validated_at`) |
| Clock moved backward or file from the future | `FromFuture`: deleted, miss |
| Oversize 200 follows a stored smaller one | Old disk copy is in `stale_on_disk`, not read through, removed |
| ENOSPC, quota, read-only filesystem | After 8 consecutive persistent failures `Unavailable` for the session, one warn |
| Antivirus rename failure on Windows | Transient, never counted |
| Offline at startup | Disk read is local; `Fresh` and `Revalidate` served |
| `cache.persistence = "memory"` applied live | Reads and writes stop immediately; files remain |
| Credentialed GitHub request (`GITHUB_TOKEN`) | Never persisted (5000/h quota, free 304s) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 *(restated, approved)* | GitHub API requests for at least 10 GitHub-sourced pins validated within the window, after restarting deps-lsp or re-running deps-cli | **0** until the window elapses, checked by `/rate_limit` `core.used` staying the same (live check with persistence enabled, procedure in the playbook) |
| SC-002 | Time from the first hover request to the first hover response after a restart, for a workspace with at least 10 pins whose entries are fresh on disk, measured live (median of 5 runs, `RUST_LOG=debug`) against a cold-start run (`cache.persistence = "memory"`) on the same workspace and machine | Warm median at most the cold median plus 50 ms; and the first request wave performs 0 network requests for those pins (every concurrent first-wave read hits the disk, verified by an integration test of FR-002); traced to T012 and T021 |
| SC-003 *(restated, approved)* | Restored entry served unrevalidated more than 10 min after its last validation | Zero cases under adversarial tests (clock skew, dropped puts, racing writers, mixed-age pages) |
| SC-004 | Crashes or corrupt reads under concurrent multi-process access | Zero across the two-process test |
| SC-005 | Files written to a developer's or runner's real cache directory by the test suite | Zero (CI guard, NFR-007) |

> [!important] Approved change to SC-001 and SC-003
> **Original SC-001**: reduced request count, target TBD. **Original SC-003**: restored entry never fresher than the in-memory policy would allow. **Reason**: see US-002 (anonymous 304 spends quota; R2 chosen by the user).

## 8. Agent Boundaries

### Always (without asking)
- Run the full pre-PR check suite from `.claude/rules/branching.md` after each PR's changes.
- Verify behavior live (Registry Integration Gate) with persistence set to `memory` or `<cache>/deps-lsp` deleted, except for the SC-001 procedure, which needs it enabled.
- Reuse `deps-core` helpers (`fs_probe`, `pagination`, `redact`) rather than ecosystem-local code.

### Ask First
- Any new dependency.
- Changing the window, budgets, host list or query-key set.
- Persisting any non-`Baseline` tier or any credentialed request.
- Adding `Durability::{Synced, Unsynced}` (only if the PR-B macOS measurement shows more than 10% of puts dropped).

### Never
- Write a credential, digest, token or non-`Accept` header to disk.
- Create a directory or file not owned by the probe uid, or create the root outside the FR-014 conditions.
- Make `HttpCache::new()` default to disk; put loopback admission behind `feature = "test-util"`.
- Edit `book/` (only the `tech-writer` agent) or `crates/deps-zed`.
- Close #700 from PR-A or PR-B.

## 9. Open Questions

None. All clarification items from the research draft are resolved below.

| # | Original item | Decision |
|---|---------------|----------|
| D-1 | Backend crate | std + `serde_json` + `fs_probe`, no new dependency; rejected `redb` and `fjall` (exclusive process lock breaks US-003), `sled` (unmaintained), `rusqlite` (C build, cross targets), `cacache` (heavy tree) |
| D-2 | Directory | OS cache directory via env-resolved `CacheDir::user_default(env)` + `deps-lsp/http/v1`; rejected workspace `.deps-lsp/` and a configurable path |
| D-3 | `Instant` vs wall clock | File mtime is the wall-clock last-validation stamp (R2); `Instant` untouched |
| D-4 | Eviction budget | Independent disk budget 64 MiB / 2048 files, 7-day cap, least recently validated first |
| D-5 | Opt-in vs default | Default-on, `memory` disables (user decision) |
| D-6 | Concurrency | Per-key atomic rename, newest validation wins; no lock file |
| D-7 | Tiers | `Baseline` + anonymous only; `Pinned` and `WorkspaceDeclared` excluded |
| D-8 | `test-util` surface | `#[cfg(test)]` loopback admission in deps-core, no new `test-util` surface |
| D-9 | Competitor evaluation | Not required once the user chose to implement |

## 10. See Also

- [[plan]] — technical plan with contracts
- [[tasks]] — implementation tasks per stacked PR
- [[constitution]] — project principles (active; compliance checked in [[plan]] §10)
- [[MOC-specs]] — all specifications
- [[031-github-actions-sha-pin-diagnostic/spec]] and [[039-github-rate-limit-actionable-diagnostic/spec]] — rate-limit motivation
- [[041-credential-redaction-hardening/spec]] and [[045-secret-accessor-auditable-naming/spec]] — secret constraints behind FR-009
- [[024-net-policy-dns-rebinding/spec]] — origin of the tier separation behind FR-008
- [[044-precommit-hooks-ecosystem/spec]] — prospective GitHub-sourced ecosystem
- `crates/deps-core/src/cache/` — `HttpCache`, `CachedResponse`, `CacheTier`
- `.claude/rules/continuous-improvement.md` — Registry Integration Gate and research scope

---
aliases:
  - GitHub Token Redaction
  - Trusted-Origin Pin for Authenticated Fetches
tags:
  - sdd
  - spec
  - security
  - deps-core
  - deps-swift
created: 2026-09-02
status: shipped
related:
  - "[[constitution]]"
  - "[[039-github-rate-limit-actionable-diagnostic/spec|Actionable rate-limit hint in registry diagnostics]]"
---

# Feature: Redact GitHub Auth Token and Pin Authenticated Fetches to a Trusted Origin

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Status**: Shipped — PR #487 (issue #484)
> **Priority**: P3 (non-urgent hardening — no exploitable issue existed prior to this change)
> **Type**: security/hardening

Retroactive spec, written after ship per the project's spec-coverage policy — this documents already-implemented, already-merged behavior rather than driving new implementation.

## 1. Overview

### Problem Statement

During the security review for [[039-github-rate-limit-actionable-diagnostic/spec|issue #478]], `crates/deps-core/src/github.rs`'s GitHub API token handling was audited end to end. No exploitable issue was found — the token was already header-only, never logged, never embedded in a URL, and redirect-safe (`reqwest` strips the `Authorization` header on cross-origin redirects). The audit did surface two defense-in-depth gaps worth closing pre-emptively:

- The raw token was stored as a bare `String`, one accidental `#[derive(Debug)]` or stray `{:?}` away from being logged in full.
- Each authenticated call site built its own header list and called the generic cache-fetch path directly, with no single choke point enforcing that authenticated requests only ever reach the intended GitHub API origin.

### Goal (shipped)

- New `AuthToken` newtype (mirroring `deps_cargo::config::AuthToken`) wraps the
  token with custom `Debug`/`Display` impls that always render `AuthToken(***)`,
  so it cannot leak via a `Debug` derive or similar formatting regardless of
  future refactors.
- New `GithubTagsClient::fetch_authenticated` is the sole entry point for
  authenticated GitHub requests. It applies the origin-pinned
  `get_cached_trusted_origin_with_headers` cache variant internally, so every
  authenticated call is defense-in-depth pinned to the trusted GitHub API
  origin regardless of what URL a caller constructs.
- `deps-swift`'s two authenticated call sites (release-dates fetch, repo
  search) are migrated onto `fetch_authenticated`.
- `GithubTagsClient::headers()` is demoted from `pub` to `pub(crate)` now that
  nothing outside `deps-core` needs the raw header list.

### Out of Scope

- Any change to how the token is sourced (environment variable, vault, etc.)
  — out of scope, this PR only hardens handling of the token once obtained.
- The actionable rate-limit diagnostic — that is
  [[039-github-rate-limit-actionable-diagnostic/spec|the sibling issue (#478)]]
  whose review surfaced this hardening opportunity.

## 2. User Stories

### US-001: Token never leaks via Debug formatting

AS A maintainer of `deps-core`
I WANT the GitHub auth token to be structurally unable to leak via `{:?}` or a
future `#[derive(Debug)]`
SO THAT a careless future change (e.g. deriving `Debug` on `GithubTagsClient`
or a struct embedding it) cannot silently start logging the token in full

**Acceptance criteria (verified shipped):**
```
GIVEN an AuthToken wrapping a real bearer token value
WHEN it is formatted with {:?} or embedded in a larger Debug-derived struct
THEN the output is exactly "AuthToken(***)" — the real value never appears
  (test_auth_token_debug_redacted, test_auth_token_redacted_in_containing_struct)
```

### US-002: Authenticated requests are pinned to the trusted GitHub origin

AS A maintainer of `deps-core`
I WANT every authenticated GitHub request to go through one choke point that
enforces the trusted-origin pin
SO THAT no future call site can accidentally send the token to an
unintended host

**Acceptance criteria (verified shipped):**
```
GIVEN GithubTagsClient::fetch_authenticated(url)
WHEN url resolves outside the trusted GitHub API origin
THEN the origin-pinned cache variant rejects/redirects-safely rather than
  attaching the Authorization header
  (wire-level mockito tests confirming cross-origin redirects are blocked)
```

### US-003: deps-swift's authenticated call sites use the shared choke point

AS A maintainer of `deps-swift`
I WANT the release-dates fetch and repo-search call sites to use
`fetch_authenticated` instead of building headers manually
SO THAT they automatically inherit the redaction and origin-pinning
guarantees without duplicating the logic

**Acceptance criteria (verified shipped):**
```
GIVEN deps-swift's release-dates fetch and repo-search paths
WHEN they perform an authenticated GitHub request
THEN both call GithubTagsClient::fetch_authenticated, not headers() directly
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL wrap the GitHub auth token in an `AuthToken` newtype with `Debug`/`Display` impls that always render `AuthToken(***)` | must |
| FR-002 | THE SYSTEM SHALL expose `GithubTagsClient::fetch_authenticated` as the sole public entry point for authenticated GitHub requests | must |
| FR-003 | `fetch_authenticated` SHALL apply the origin-pinned `get_cached_trusted_origin_with_headers` cache variant internally | must |
| FR-004 | THE SYSTEM SHALL migrate all `deps-swift` authenticated call sites onto `fetch_authenticated` | must |
| FR-005 | THE SYSTEM SHALL demote `GithubTagsClient::headers()` to `pub(crate)` | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Token cannot leak via `Debug`/`Display` formatting, by construction, independent of future refactors |
| NFR-002 | Security | Authenticated requests are defense-in-depth pinned to the trusted GitHub API origin even if a caller constructs an unexpected URL |
| NFR-003 | Compatibility | No behavior change for existing callers — the token still reaches the wire identically; only its handling in-process is hardened |

## 5. Data Model

| Entity | Description | Change |
|--------|-------------|--------|
| `AuthToken` (new, `deps-core::github`) | Newtype wrapping the bearer token string | New — mirrors `deps_cargo::config::AuthToken` |
| `GithubTagsClient::auth_headers: Vec<(HeaderName, AuthToken)>` | Stored authenticated headers | Value type changed from raw `String` to `AuthToken` |
| `GithubTagsClient::fetch_authenticated` (new method) | Sole authenticated-fetch entry point | New — applies trusted-origin pin internally |
| `GithubTagsClient::headers()` (existing) | Raw header accessor | Visibility narrowed `pub` -> `pub(crate)` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior (shipped) |
|----------|-------------------|
| `AuthToken` embedded in a struct that later gains `#[derive(Debug)]` | Still renders `AuthToken(***)` — redaction is structural, not call-site-dependent |
| Authenticated fetch redirected cross-origin | `Authorization` header not carried across (both `reqwest`'s existing behavior and the origin-pinned cache variant's defense-in-depth) |
| `deps-swift` call site invoking `fetch_authenticated` with a same-origin URL | Request proceeds normally, token reaches the wire as before |

## 7. Success Criteria

| ID | Metric | Target (verified shipped) |
|----|--------|--------|
| SC-001 | `AuthToken` Debug/Display output never contains the raw token | Pass — dedicated redaction tests |
| SC-002 | Wire-level tests confirm token still reaches the wire and cross-origin redirects are blocked | Pass — new mockito tests |
| SC-003 | Full CI suite green | Pass — fmt/clippy/nextest/rustdoc gates clean |

## 8. Agent Boundaries

### Always (without asking)
- Route any new authenticated GitHub call site through
  `GithubTagsClient::fetch_authenticated`, never build headers manually
  outside `deps-core`.

### Ask First
- Exposing `GithubTagsClient::headers()` (or the raw token) as `pub` again —
  the whole point of this hardening was to make `fetch_authenticated` the
  only path.

### Never
- Derive `Debug` on `AuthToken` directly (bypassing the manual impl) or store
  the raw token as a bare `String` anywhere it could be formatted.

## 9. Open Questions

None — implemented and merged.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[039-github-rate-limit-actionable-diagnostic/spec|Actionable rate-limit hint in registry diagnostics]] — the sibling issue whose security review surfaced this hardening
- `crates/deps-core/src/github.rs` — `AuthToken`, `GithubTagsClient::fetch_authenticated`
- Issue #484, PR #487 (commit `92cac087`)

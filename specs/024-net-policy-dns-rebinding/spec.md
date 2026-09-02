---
aliases:
  - DNS Rebinding Bypass of net_policy
  - net_policy DNS Rebinding
tags:
  - sdd
  - spec
  - security
  - research
  - net-policy
created: 2026-09-01
status: shipped
related:
  - "[[constitution]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
---

# Feature: Resolved-Address Validation for `net_policy` (Close DNS-Rebinding Bypass of the Workspace-Registry SSRF Classifier)

> [!info] Metadata
> **Author**: rust-researcher (CI cycle 018)
> **Branch**: research/024-net-policy-dns-rebinding (superseded — shipped across two PRs, see Status)
> **Priority**: P3 (research / security-hardening follow-up)
> **Status**: Shipped in two stages — PR #457 (issue #449) closed the policy-independent `never_a_registry` tier (loopback/link-local/cloud-metadata/unspecified) via a connect-time `reqwest::dns::Resolve` guard (`BlockedAddrResolver`) wired into the shared client pool, plus NAT64-embedded-address unwrapping; PR #460 (issue #455) closed the remaining `PublicOnly`-policy-aware tier (RFC1918/CGNAT) at both connect time and on every redirect hop via a policy-snapshotted `Transport`/`AddrGuard`. All of FR-001 through FR-007 below are satisfied by the combination of the two PRs. `cargo.workspace_registries = off` remains an unaffected, complete mitigation (US-002).

## 1. Overview

### Problem Statement

PR #447 (merged 2026-09-01, commit `a8779b43`) introduced [[net_policy|`deps-core::net_policy`]]
(`crates/deps-core/src/net_policy.rs`) to close the SSRF/reachability-probing gap tracked by
issue `#443`. `RegistryAccessPolicy`/`classify_host` blocks workspace-declared Cargo
registry/source URLs — and every redirect hop reached while fetching them — whose *host
string* falls into a blocked `HostClass` (loopback, link-local, cloud-metadata, RFC1918,
CGNAT, unique-local IPv6, unspecified, or internal-name), gated by the
`cargo.workspace_registries` setting (`off` / `public_only` / `all`, default `public_only`).

The classifier's own module doc and the `HostClass` doc are explicit that classification is
computed **from the URL string alone, with no DNS resolution**. This leaves a
[DNS-rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) gap: a hostname that is not
itself a blocked literal but *resolves* to a blocked address is never caught. A hostile
repository can declare a `registry-index`/`[source]` URL using a hostname the attacker
controls DNS for. At the moment `classify_host` validates the string, public DNS resolves it
to an innocuous public IP, so `HostClass::Global` passes the `public_only` gate. By the time
(or shortly after) `reqwest` performs the actual HTTPS GET, the attacker has rebound the
record's A/AAAA answer to `169.254.169.254` (cloud metadata) or an RFC1918 address — the
connection lands on the blocked-in-intent internal target anyway, because `reqwest`'s
connector resolves DNS itself at connect time, independent of, and later than, the
string-based classification already performed. This is a textbook TOCTOU (time-of-check to
time-of-use) gap: the check and the use are separated by a DNS resolution the attacker
controls.

This is not a bug in `classify_host`'s own rule completeness (issue `#443` and PR #447 already
closed every string-based bypass found during design review, including the trailing-dot
hostname bypass). It is a structural limitation of validating a *reference* to a network
resource rather than the resource's actual resolved address at the point of use — and it was
explicitly named and deferred by PR #447 itself ("D1 in the implementation plan"), but no
GitHub issue or spec was ever filed for it. `gh issue list` searches for "DNS rebinding",
"net_policy", "classify_host", and "resolver Resolve" (2026-09-01) returned zero results, and
a full-text grep of `.local/specs/` and `.local/` for "DNS rebinding"/"D1" found no matching
tracking artifact — `.local/specs/023-cargo-custom-registries/`'s own D1 reference is an
unrelated design-review item. This spec exists to close that tracking gap and define the
functional shape of the eventual fix, without prescribing its full implementation.

### Goal

A future fix will validate the **resolved IP address actually connected to**, not just the
declared hostname string, against the same `HostClass` blocklist `classify_host` already
enforces — for every workspace-declared registry/source fetch and every redirect hop, across
all 11 ecosystem crates that share the `reqwest` client pool — closing the rebinding TOCTOU
gap while preserving today's zero-behavior-change guarantee for legitimate public registries.

### Out of Scope

- Redesigning `HostClass` or its classification rules (string-based coverage is considered
  complete as of PR #447; this spec is only about *when* the check happens, not *what* it
  checks for).
- Any change to `$CARGO_HOME`-declared registries (out of the SSRF threat model per PR #447 —
  they are not workspace-attacker-controlled).
- Non-Cargo ecosystems' own workspace-declared-URL features, since none currently exist — this
  spec documents that any future one would inherit the same gap via the shared client pool,
  but does not design for a feature that does not yet exist.
- Full implementation of the `reqwest::dns::Resolve` (or equivalent) fix — the code comments
  and PR #447 body already sketch this direction; this spec captures requirements and
  acceptance criteria for that eventual implementation, not its design.
- General-purpose DNS-rebinding protection for LSP traffic unrelated to workspace-declared
  registry/source URLs (e.g., OSV.dev, npm registry, PyPI registry — these are
  operator/server-declared endpoints, not attacker-controlled, and are out of the original
  `#443` threat model).

## 2. User Stories

### US-001: Protect a developer opening a hostile repository from a rebinding-based SSRF

AS A developer using `deps-lsp` on an untrusted or unreviewed repository
I WANT the LSP to refuse to actually connect to an internal/cloud-metadata address even if
the workspace-declared registry hostname passed string-based validation
SO THAT a hostile `Cargo.toml`/`.cargo/config.toml` cannot use DNS rebinding to make my
editor's background fetch reach my internal network or my cloud instance's metadata endpoint.

**Acceptance criteria:**
```
GIVEN a workspace declares a registry-index URL whose hostname resolves, at validation time,
  to a public IP address (passing HostClass::Global under `public_only`)
WHEN the actual HTTP client connects to fetch that URL and DNS now resolves the same hostname
  to an address in a blocked HostClass (e.g. 169.254.169.254, or an RFC1918 address)
THEN the fetch SHALL be aborted before the connection is used, and the failure SHALL be
  attributed to the resolved-address check (not silently treated as a generic network error)
```

### US-002: Preserve today's coarse workaround for users who need it now

AS A security-conscious user who cannot wait for the resolved-address fix
I WANT `cargo.workspace_registries = off` to remain a complete boundary against both the
already-closed string-based bypass and this DNS-rebinding gap
SO THAT I have a working mitigation today, independent of when the eventual fix ships.

**Acceptance criteria:**
```
GIVEN cargo.workspace_registries is set to `off`
WHEN a workspace declares any registry-index/[source] URL, regardless of hostname or DNS
  behavior
THEN the LSP SHALL NOT fetch it, exactly as today — this spec's eventual fix SHALL NOT change
  `off`'s behavior or scope
```

### US-003: No functional regression for legitimate public/private registries

AS A developer using a legitimate public registry (crates.io mirror) or an internal corporate
registry reachable over a private network under `all`
I WANT the resolved-address check to accept my registry's actual resolved address exactly as
`classify_host` accepts its hostname today
SO THAT closing the rebinding gap does not break workspaces that were working correctly before.

**Acceptance criteria:**
```
GIVEN a registry-index hostname whose resolved address is consistently HostClass::Global
  (public registry) or, under `all`, a class explicitly permitted by the active policy
WHEN the resolved-address check runs at connect time
THEN the fetch SHALL proceed exactly as it does today, with no added latency budget beyond
  what DNS resolution and connection already cost
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the HTTP client resolves DNS for a workspace-declared registry/source URL (or a redirect hop from one) THE SYSTEM SHALL classify every resolved IP address against the same `HostClass` blocklist `classify_host` uses for the string-based check | must |
| FR-002 | WHEN a resolved address falls into a `HostClass` blocked by the active `WorkspaceRegistryAccess` policy (`public_only` or a future narrower `all` restriction) THE SYSTEM SHALL abort the connection before any request is sent and SHALL NOT reuse or cache the response | must |
| FR-003 | WHEN a hostname resolves to multiple addresses (A/AAAA records) THE SYSTEM SHALL classify every returned address, not only the first one selected for connection, so an attacker cannot hide a blocked address behind an earlier innocuous one | must |
| FR-004 | WHEN the resolved-address check blocks a connection THE SYSTEM SHALL surface a diagnostic/log message that distinguishes this case from a generic connection failure, naming the blocked `HostClass` (consistent with `classify_host`'s existing `Display` labels) | should |
| FR-005 | WHEN `cargo.workspace_registries` is `off` THE SYSTEM SHALL continue to reject the URL before any DNS resolution occurs, unaffected by this feature | must |
| FR-006 | WHEN the resolved-address check is added THE SYSTEM SHALL apply it identically across all 11 ecosystem crates sharing the `reqwest` client pool, not only `deps-cargo`, so a future workspace-declared-URL feature in another ecosystem inherits the protection automatically | should |
| FR-007 | WHEN a redirect hop's resolved address is blocked THE SYSTEM SHALL apply the same resolved-address check as the initial request, consistent with the existing redirect-hop string-based reclassification hardening from PR #447 | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The resolved-address check SHALL add no observable latency beyond DNS resolution + connection time already incurred by the request — no additional round-trip (e.g., no separate resolve-then-reconnect step distinguishable from normal TCP/TLS connect timing) |
| NFR-002 | Architecture | The fix SHALL be implemented at the shared `reqwest` client-pool layer (e.g., a custom `reqwest::dns::Resolve`, or equivalent address-pinning at connect time) so it is inherited by all 11 ecosystem crates without per-crate duplication — consistent with `net_policy`'s existing placement rationale (DRY, no ecosystem-specific `#[cfg(feature = ...)]` gate) |
| NFR-003 | Reliability | Legitimate registries whose resolved address is consistently public SHALL see zero behavior change — verified by the existing `deps-cargo` test suite (and equivalent suites in other ecosystem crates) passing unmodified |
| NFR-004 | Security | The check SHALL be fail-closed: if address resolution cannot be classified (e.g., resolver error, unexpected address family) THE SYSTEM SHALL treat the connection as blocked rather than allowed, consistent with `net_policy`'s existing conservative bias |
| NFR-005 | Maintainability | The resolved-address `HostClass` check SHALL reuse `classify_ip`/`unwrap_mapped_v4` from `crates/deps-core/src/net_policy.rs` rather than duplicating classification logic — the same DRY rationale that placed `net_policy` in `deps-core` applies to its reuse here |

## 5. Data Model

No new persistent entities. This feature extends the *evaluation point* of the existing
`HostClass`/`WorkspaceRegistryAccess` model (see [[net_policy]]), not its data shape.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `HostClass` (existing) | Classification of a host, reused unchanged for resolved addresses | `Loopback`, `LinkLocal`, `CloudMetadata`, `PrivateV4`, `Cgnat`, `UniqueLocalV6`, `Unspecified`, `InternalName`, `Global` |
| `WorkspaceRegistryAccess` (existing) | Live-updatable policy switch, unchanged semantics | `Off`, `PublicOnly`, `All` |
| Resolved-address check (new, unnamed) | The connect-time gate this spec requires; naming and exact placement (custom `Resolve` impl vs. connector-level hook) left to the implementation | evaluates every A/AAAA address returned for a workspace-declared host against `HostClass` before the connection is used |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Hostname resolves to a mix of public and blocked addresses (multi-A-record) | Blocked per FR-003 — any blocked address in the resolved set aborts the connection, even if a public address is also present |
| DNS TTL expires and re-resolves to a blocked address *after* a first successful connection in the same session | [NEEDS CLARIFICATION: whether per-connection re-validation is required for long-lived/pooled connections, or whether validating once per new TCP connection attempt is sufficient — affects `reqwest` connection-pool reuse behavior] |
| Resolver returns no addresses / resolution fails | Fail-closed per NFR-004 — treated as blocked, not silently skipped |
| IPv4-mapped IPv6 resolved address (`::ffff:169.254.169.254`) | Unwrapped via the existing `unwrap_mapped_v4` helper before classification, consistent with the string-based check |
| `cargo.workspace_registries = off` | No DNS resolution attempted at all — request rejected before resolve, unaffected by this feature (FR-005) |
| Corporate registry under `all` whose hostname legitimately resolves to an RFC1918 address | Not blocked — `all` policy already permits `PrivateV4`/`Cgnat`/`UniqueLocalV6`/`InternalName` per `HostClass::never_a_registry`'s narrower definition; only `never_a_registry`-class resolved addresses are blocked under `all` |
| A redirect hop's target resolves to a blocked address | Blocked per FR-007, consistent with existing redirect-hop string-based hardening |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Tracking artifact exists for this follow-up | This spec file exists and is linked from `MOC-specs.md` and `net_policy.rs`'s doc comment (non-code deliverable of this CI cycle) |
| SC-002 | Rebinding attempt blocked | Shipped — `deps-core/src/cache.rs`'s `test_validate_resolved_addrs_*` unit tests and PR #460's `TestLookup`-driven `BlockedAddrResolver` integration tests cover both the `never_a_registry` tier (PR #457) and the `PublicOnly`-policy RFC1918/CGNAT tier (PR #460) rejecting a resolved address at connect time |
| SC-003 | No regression | Shipped — the existing `deps-cargo`/workspace test suite passes unmodified; `mockito`-based tests (which bind IP literals, never hostnames) are unaffected since literals never reach the configured resolver |
| SC-004 | No added latency | Shipped — the guard adds one in-process classification per already-occurring DNS resolution, no extra round-trip; not separately benchmarked beyond the existing test suite's timing tolerances |

## 8. Agent Boundaries

### Always (without asking)
- Cite `crates/deps-core/src/net_policy.rs`, issue `#443`, and PR #447 as prior art when
  implementing the eventual fix — do not re-derive `HostClass` classification logic.
- Run the full CI check suite (fmt, clippy, nextest, rustdoc gate) before any implementation PR
  for this spec, per project convention.

### Ask First
- Choosing the specific `reqwest::dns::Resolve` (or equivalent) implementation strategy —
  multiple valid approaches exist (custom resolver, connector-level IP pinning,
  `hickory-resolver` integration) and the choice affects the shared client-pool architecture
  used by all 11 ecosystem crates.
- Any change to `WorkspaceRegistryAccess`'s public enum shape or default policy value.

### Never
- Implement this fix by re-adding DNS resolution to `classify_host` itself — the string-based
  classifier is deliberately resolution-free (see its module doc); the fix belongs at the
  connection layer, not the classification layer.
- Change `off`'s behavior or scope as part of this fix (US-002).
- Silently downgrade the fail-closed default (NFR-004) to fail-open for convenience or
  performance.

## 9. Open Questions

All resolved by the shipped implementation:

- Connection-pool re-validation cadence: resolved — `BlockedAddrResolver` is a
  `reqwest::dns::Resolve` implementation, invoked by `reqwest`'s connector on every new
  connection attempt (not on reuse of an already-pooled connection), which the shipped design
  accepts as sufficient (validating once per new TCP connection attempt).
- Which `reqwest` DNS-resolution hook point to use: resolved — a custom `reqwest::dns::Resolve`
  (`BlockedAddrResolver`), wired once at `build_client`/`Transport` construction, the workspace's
  sole `Client::builder()` call site.
- Whether the fix composes with PR #447's redirect-hop string-based reclassification: resolved —
  a redirect hop reuses the same `Client`, so `BlockedAddrResolver` validates its resolved
  address too, "for free," alongside the existing string-based `hop_targets_blocked_host` check;
  PR #460 additionally threads the policy-aware `AddrGuard` tier into the redirect policy itself
  for the RFC1918/CGNAT case.

## 10. See Also

- [[net_policy|`crates/deps-core/src/net_policy.rs`]] — the string-based classifier this spec extends, now also exposing `classify_addr` for resolved-address classification
- Issue `#443` — original SSRF/reachability-probing gap that PR #447 closed
- PR `#447` — introduced `net_policy`, named this gap "D1 in the implementation plan," deferred it as a follow-up
- Issue `#449`, PR `#457` — closed the policy-independent `never_a_registry` tier of this gap (`BlockedAddrResolver`, NAT64 unwrapping)
- Issue `#455`, PR `#460` — closed the remaining `PublicOnly`-policy-aware (RFC1918/CGNAT) tier, at connect time and on redirect hops (`Transport`/`AddrGuard`)
- [[023-cargo-custom-registries/spec#4-non-functional-requirements|023-cargo-custom-registries spec, NFR-003]] — the original residual-risk sign-off this gap traces back to
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications

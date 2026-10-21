---
tags:
  - sdd
  - plan
  - ecosystem/swift
  - deps-core
created: 2026-10-21
status: plan
related:
  - "[[spec]]"
  - "[[tasks]]"
  - "[[MOC-specs]]"
  - "[[086-git-ref-probe-branch-evidence/plan|086 plan]]"
---

# Plan: Swift SCM-to-registry swizzling (#1757)

## 1. Architecture

```
parse_manifest (no network)
  swizzle_decision(mode, trusted user-tier default, form, ScmLookupUrl, memo answer)
    Scm                -> today's SCM dependency
    RegistryIdentity   -> id: dependency { name: scope.name, source: AlternateRegistry, origin: Swizzled{scm} }
PreFetch (open/change only): await identifiers lookups for memo misses
    detached per-URL single-flight task -> GET {default}/identifiers?url=... -> memo (generation++ on change)
    Reparse iff swizzle_decision differs from parsed form
memo generation change -> RefreshEvent::ReparseOpenDocuments { generation } (coalesced 1 s/ecosystem)
reparse paths run no PreFetch and no probe
registry fetch (id: route reused) -> PostFetch (no-op for Swift) -> classify
OSV / license: OsvNaming::public_content(dep) at 5 sites
```

## 2. Components

| Crate | Item |
|-------|------|
| deps-core `policy_config.rs` | `ScmToRegistry`, `PolicyConfigDiff` entry (`swift_scm_to_registry_changed`) |
| deps-core `redact` | `strip_url_credentials(raw) -> Option<url::Url>` |
| deps-core `osv` / `lsp_helpers` / `conformance.rs` | `OsvNaming::public_content` + `PublicContent<'d>`; 5 call sites; conformance fixture |
| deps-core `tag_index_refresh.rs` (086) | `RefreshEvent::ReparseOpenDocuments { generation }` |
| deps-swift `config.rs` | mode wiring |
| deps-swift `package_registry.rs` | identifiers endpoint, `IdentityLookup`, `RegistryIdentity::parse` gate |
| deps-swift `parser.rs` | `SwiftRequirementForm`, `SwiftOrigin`, memo read, `swizzle_decision` call |
| deps-swift `registry.rs` / new `scm_memo.rs` | `ScmIdentityMemo` (stale-while-revalidate, idle eviction, generation), detached single-flight |
| deps-swift `formatter.rs` | `public_content` override, `osv_package_name`, hover provenance line |
| deps-engine `setup.rs` / probe module | PreFetch ordering for CLI, incomplete-lookup note |
| deps-lsp | config diff reaction (reparse all Swift docs), `ReparseOpenDocuments` listener, PreFetch before the fetch on open/change |
| deps-cli | `ignored_sections` entry; stderr note |
| docs | book `swift.md`; CHANGELOG |

## 3. Design notes

- `swizzle_decision` is a pure function in deps-swift; unit-tested with an exhaustive truth table.
- Detached lookups: the single-flight owns a spawned task per `ScmLookupUrl`; waiters hold a `watch`/`Shared` handle; aborting a waiter never cancels the task.
- `ParseTrigger { Content, Config, Memo }` selects whether PreFetch and probes run (never for Memo). Memo key is `(lookup registry URL, canonical SCM URL)`.
- Generation guard: `(content_version, generation)` applied at most once per document.
- `public_content` default preserves behavior; Swift override returns `Owned` with case-preserving `owner/repo` from `url_to_identity`.
- License: request by `public_content.name`, store by `PackageKey::new(dep.name(), formatter).normalized()`.
- Unlike 086/087 this feature uses no `ProbeAllowance`; bounds are FetchConcurrency, FetchTimeout, gate/breaker, per-URL single-flight and 1 h TTL.

## 4. Security

Trust gate (user tier, `Trusted`) enforced inside `swizzle_decision` and the lookup client; project tier never queried; credential stripping via the shared `redact` helper; `HostBlockedByPolicy` on the registry host; memo stores only validated identities.

## 5. Risks and rollout

Convergence and flapping are the main risks, covered by the pure decision, SWR memo, reparse-runs-nothing rule and generation guard. Wire-URL/canonical mismatch covered by the one canonical retry. Ships after 086 (needs `ProbePhase`, `RefreshEvent`). Docs: book `swift.md`.

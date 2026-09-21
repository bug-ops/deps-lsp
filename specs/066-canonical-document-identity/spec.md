---
aliases:
  - Canonical Document Identity
tags:
  - sdd
  - spec
  - deps-lsp
  - lsp-protocol
created: 2026-09-20
status: shipped
related:
  - "[[constitution]]"
  - "[[063-deps-core-domain-boundary-hardening/spec]]"
---

# Feature: Canonical Document Identity

> [!info] Metadata
> **Author**: Andrei G
> **Branch**: feat/1086-canonical-document-identity
> **Issue**: #1086

## 1. Overview

### Problem Statement

`url::Url::parse` (WHATWG URL Standard) normalizes several valid client URI
spellings that `tower_lsp_server::ls_types::Uri` (RFC 3986, via `fluent-uri`)
accepts as-is: `file://localhost/x` -> `file:///x`, `FILE:///x` -> `file:///x`,
`.`/`..` segment collapsing, `file:////server/share/x` -> UNC form
`file:///server/share/x`. `ServerState::documents` is keyed by the client's
literal `Uri` string (`DashMap<Uri, DocumentState>`), not by a normalized
form — so two requests that spell the same physical file differently are, as
of today, treated as two distinct documents with no relationship to each
other.

Separately, several handlers convert the request `Uri` to `url::Url` via
`crate::lsp_types_interop::from_lsp_uri` for path-based logic (ecosystem
routing, sibling-manifest lookups), then build response data from that
normalized `url::Url`. When a response's URI is derived from the normalized
form instead of the original request `Uri`, the client receives a URI string
it doesn't recognize as the document it has open, silently breaking a
`WorkspaceEdit.changes` map key, a code-lens command argument (looked up
against `ServerState::documents`), or a diagnostic's `related_information`
`Location`.

PR for issue #1071 fixed this reactively, per call site, by re-substituting
the original client `Uri` at three identified leak points
(`handlers/code_actions.rs`'s `rekey_edits_to_original_uri`,
`handlers/code_lens.rs`'s command arguments, `deps-core`'s
`lsp_helpers/diagnostics.rs`'s `related_information` locations). This closes
the three found instances but not the bug class: a fourth leak point, or a
handler added later, can reintroduce it, since nothing centrally enforces
"every URI leaving the server matches the identity the client used to open
the document."

### Goal

Every LSP-protocol-facing URI in `deps-lsp` — the `ServerState::documents`
key, and every URI value in a request/response — is derived from one
canonical representation, computed once, so per-handler rekeying logic
(`rekey_edits_to_original_uri` and its two counterparts) can be deleted
rather than replicated at new call sites.

### Out of Scope

- Coalescing *different* schemes referring to the same resource (e.g. a
  `file:` URI and a `vscode-remote:` URI mapping to the same underlying
  path) — this feature only collapses different *spellings of the same
  scheme+authority+path* URI shape.
- Changing `from_lsp_uri`'s existing rejection behavior for
  `FileWithHostAndWindowsDrive` (issue #1090) or any other URI the WHATWG
  parser rejects/mangles for security reasons — those documents remain
  untracked (`EcosystemRegistry::for_uri` already returns `None` for them),
  unaffected by this change.
- Editor-side URI normalization behavior (out of `deps-lsp`'s control).

## 2. User Stories

### US-001: Consistent document identity across differently-spelled requests

AS A user of an LSP client that spells the same open document's URI
differently across requests (e.g. `didOpen` with `file://localhost/x.toml`,
then a `codeAction` request the client itself re-issues as
`file:///x.toml`)
I WANT `deps-lsp` to treat both requests as operating on the same document
SO THAT my diagnostics, completions, and code actions stay in sync instead of
one spelling seeing stale/absent state because the server tracked it as a
second, empty document

**Acceptance criteria:**
```
GIVEN a document opened via didOpen with URI spelling A
WHEN a later request for the same physical file arrives with equivalent
     URI spelling B (differs only in WHATWG-normalized form)
THEN the server resolves both to the same DocumentState entry
```

### US-002: No per-handler URI rekeying required

AS A `deps-lsp` maintainer adding a new LSP handler
I WANT the server to guarantee outgoing URIs already match the canonical
identity used to store the document
SO THAT I do not need to remember to add a `rekey_edits_to_original_uri`-style
fixup at my new call site to avoid reintroducing the bug class from #1071

**Acceptance criteria:**
```
GIVEN a new handler that looks up ServerState::documents and returns a
      response containing a URI
WHEN it uses the canonical Uri already resolved for the request
THEN no additional per-handler rekeying logic is needed for the returned URI
     to match a key the client recognizes
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a `textDocument/didOpen` request arrives THE SYSTEM SHALL compute one canonical `Uri` for it and use that canonical form as the sole `ServerState::documents` key | must |
| FR-002 | WHEN any subsequent request (`didChange`, `didClose`, `hover`, `completion`, `codeAction`, `codeLens`, `diagnostic`, `documentLink`, `inlayHint`, ...) carries a `textDocument.uri` THE SYSTEM SHALL canonicalize it with the same function before any `ServerState::documents` lookup | must |
| FR-003 | WHEN the system builds a response containing a URI derived from server-tracked document state THE SYSTEM SHALL use the canonical `Uri` as the returned value, not the raw per-request string | must |
| FR-004 | WHEN two requests carry URIs that canonicalize to the same value but were spelled differently by the client THE SYSTEM SHALL resolve them to the same `DocumentState` (dedup at canonicalization, not two live entries) | must |
| FR-005 | WHEN a URI cannot be canonicalized (rejected by `from_lsp_uri`, including the #1090 Windows-drive guard) THE SYSTEM SHALL keep existing behavior: treat the document as unhandled/untracked, not panic or silently fall back to the raw string as a key | must |
| FR-006 | WHEN this change lands THE SYSTEM SHALL remove `rekey_edits_to_original_uri` (`handlers/code_actions.rs`), the equivalent code-lens command-argument fixup, and the `deps-core` diagnostics `related_information` fixup, since canonical-in/canonical-out makes them redundant | should |
| FR-007 | WHEN existing call sites construct a `Uri` key for `ServerState::documents` today (`Uri::from_file_path`, request `textDocument.uri`, code-lens command args) THE SYSTEM SHALL route through the single canonicalization function rather than any ad hoc conversion | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Canonicalization must not add a syscall or registry round trip to any request path; it is a pure string/`url::Url` transform reusing the existing `from_lsp_uri`/`to_lsp_uri` machinery, safe to call inline on every handler's hot path (per constitution principle 3, non-blocking LSP surface) |
| NFR-002 | Compatibility | Must be verified against at least one real editor client (constitution principle 5: verify live, not just in CI) — confirm the client accepts a response URI in canonical form even when it originally sent a differently-spelled request URI |
| NFR-003 | Regression safety | Existing #1071 regression tests for `rekey_edits_to_original_uri` and its two counterparts must be replaced by equivalent tests asserting the *canonicalize-at-entry* invariant, not merely deleted |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ServerState::documents` | Per-document state map | Key changes from raw client `Uri` string to canonical `Uri` (derived from canonical `url::Url` via `to_lsp_uri`); value type (`DocumentState`) unchanged |
| Canonical URI | The one `url::Url`/`Uri` pair representing a document's identity, computed once per request via a shared helper | Produced by `from_lsp_uri` (existing parse/reject semantics unchanged) then normalized back via `to_lsp_uri` |

No new persisted entity — this is a keying-strategy change to an existing in-memory map.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Client sends `file://localhost/x.toml` on `didOpen`, then `file:///x.toml` on `hover` for the same file | Both canonicalize to the same key; hover sees the already-loaded `DocumentState` |
| Client sends a URI `from_lsp_uri` rejects (e.g. #1090 Windows-drive-with-host shape) | Same as today: `EcosystemRegistry::for_uri`/handler-level `None` short-circuit, no entry created, no panic |
| Client sends `.`/`..`-bearing path segments that WHATWG collapses differently than the client's own filesystem view | Server's canonical form still matches what the client resolves to on disk in every case observed so far (segment collapsing is filesystem-equivalent); this needs live verification (NFR-002), not just an assumption |
| A response would have returned an original, non-canonical `Uri` under the old per-handler rekeying (e.g. `code_actions.rs`'s `rekey_edits_to_original_uri` test fixtures) | Response now returns the canonical form instead; existing tests asserting "must equal the client's original spelling" are updated to assert "must equal the canonical form", per the accepted trade-off (see Open Questions — resolved) |
| Two *different* physical files that happen to canonicalize to the same `url::Url` (should not occur for well-formed `file:` URIs, but verify for edge inputs) | Out of scope to invent new dedup heuristics beyond what `url::Url`'s own equality already provides; if found, file as a follow-up, not blocking this feature |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `rekey_edits_to_original_uri` and its two counterparts (code_lens, diagnostics `related_information`) are deleted with no test regression | 100% removed, full test suite green |
| SC-002 | A live-editor test (per NFR-002) sends a request with a non-canonical URI spelling and confirms the server's response is accepted/matched by the client | Verified manually, documented in `.local/testing/` per continuous-improvement rules |
| SC-003 | No new `cargo clippy -D warnings` or CI regressions introduced | CI green on the feature branch |

## 8. Agent Boundaries

### Always (without asking)
- Run the full check suite (`fmt`, `clippy`, `nextest`, rustdoc gate) before considering a task done, per `.claude/rules/branching.md`
- Preserve existing `from_lsp_uri` rejection semantics (including the #1090 guard) exactly as-is
- Update/replace the existing #1071 regression tests rather than deleting them without replacement

### Ask First
- Any change to `from_lsp_uri`/`to_lsp_uri` themselves (in `deps-core`/`lsp_types_interop.rs`) beyond calling them at the new canonicalization point — this spec assumes reuse, not modification, of the existing conversion functions
- Widening this change's scope to ecosystem crates (`deps-cargo`, etc.) — this is a `deps-lsp`-binary-level concern (document identity, `ServerState`), not a `deps-core` cross-ecosystem helper, unless implementation reveals otherwise

### Never
- Silently fall back to the raw request-string key when canonicalization fails — must preserve the existing "treat as unhandled" behavior (FR-005)
- Remove the #1090 syntax-violation guard in `from_lsp_uri` as a side effect of this refactor

## 9. Open Questions

None outstanding — the two design decisions the issue flagged as needing a
"careful design pass" were resolved during spec review:

- **Dedup policy** (resolved): differently-spelled URIs for the same
  document collapse into a single `DocumentState` entry, keyed by the
  canonical form (see FR-004).
- **Response URI form** (resolved): responses always use the canonical
  form, not the client's original per-request spelling. This is the
  LSP-spec-conformant behavior (clients are expected to normalize for
  comparison), but NFR-002 requires verifying it against at least one real
  client before this is considered done.

## 10. See Also

- [[constitution]] — project principles (principles 3, 5 apply directly)
- [[MOC-specs]] — all specifications
- [[063-deps-core-domain-boundary-hardening/spec]] — the PR (#1071) whose
  reactive per-call-site fix this feature replaces with a structural one
- Issue #1086

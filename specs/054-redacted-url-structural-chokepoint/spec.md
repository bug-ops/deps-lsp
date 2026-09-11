---
aliases:
  - Redacted URL Structural Chokepoint
  - URL Redaction Chokepoint
tags:
  - sdd
  - spec
  - security
  - architecture
created: 2026-09-10
status: shipped
related:
  - "[[constitution]]"
---

# Feature: Structural Chokepoint for Outbound-URL Redaction in Error/Log Output

> [!info] Metadata
> **Author**: Andrei G.
> **Branch**: (none yet — issue #789 filed, not yet started)

## 1. Overview

### Problem Statement

`#767` found that `DepsError`'s `Display` (and, transitively, `reqwest::Error`'s own
embedded `Display`) leaked full, unredacted request URLs — including query-string
credentials such as an `.npmrc` `_authToken` or a NuGet `?ApiKey=...` — through
`tracing::warn!`/`debug!` call sites and even through `window/showMessage` editor
popups. `#775` ("fix(deps-core): redact registry URLs and credentials from error
output", merged 2026-09-10) fixed the concrete leak: `DepsError`'s `Display` and
hand-written `Debug` now route four URL-bearing variants
(`RegistryError`, `HttpStatus`, `Offline`, `ResponseTooLarge`) through
`url_for_tracing()` (`crates/deps-core/src/error.rs`), `reqwest::Error::without_url()`
is applied at `RegistryError`-wrapping construction sites, and the same
`url_for_tracing()` call was retrofitted across warn/debug/hover call sites in
`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-go`, `deps-nuget`, and `deps-maven`.

The fix is real and effective today. The problem this spec targets is what `#775`'s
own PR body flags as an explicit, admitted gap:

> "Redaction is applied per-`DepsError`-variant and per-call-site across ecosystem
> crates rather than through one enforced chokepoint (e.g. a redacting newtype for
> outbound URLs). That gap is exactly why two `deps-cargo` sites were initially
> missed during review. A follow-up issue for a stronger structural boundary would
> be worth filing separately."

No follow-up issue was ever filed (`gh issue list --search "RedactedUrl
TracingSafeUrl chokepoint redact newtype"` returns only `#767` itself, closed). This
spec is that follow-up.

**Verified extent of the pattern** (2026-09-10, current `main`): `url_for_tracing()`
is called manually at 44 sites across 14 files —
`crates/deps-core/src/{error.rs,cache.rs,github.rs,net_policy.rs,osv/mod.rs,deps_dev/mod.rs}`
and `crates/deps-{cargo,go,maven,npm,nuget,pypi}/src/{config.rs,parser.rs,sparse.rs,registry.rs}`.
Each of those 44 sites is a place where a human had to remember, unprompted by the
type system, to wrap a URL-bearing value before it reached `tracing::warn!`/`debug!`,
an `InvalidEntry`-shaped struct, or hover-visible text. Nothing prevents call site 45
(the next ecosystem crate, the next `DepsError` variant, the next registry-client
error path) from being missed exactly as the two `deps-cargo` sites were.

> [!note] Correction to the originating finding
> The finding that prompted this spec also named two "adjacent unaddressed sites"
> from `#767`'s body: `net_policy.rs`'s `validate_index_url` `BlockedHost` warn log,
> and `deps-maven/registry.rs`'s `get_metadata` fallback-loop error logs. Both were
> in fact already redacted as part of `#775`'s per-call-site sweep (verified by
> reading current source and `git blame`: `net_policy.rs:693` and
> `deps-maven/src/registry.rs`'s fallback loop both call `url_for_tracing()` on
> current `main`, landing in commit `858c06577`, PR `#775`). They are **not** open
> leaks. They remain useful as in-scope examples of the same call-site pattern —
> both were fixed ad hoc, by the same discipline-dependent process that missed the
> two `deps-cargo` sites — not as unresolved instances of the bug.

### Goal

A new call site that stores or logs an outbound URL inside a `DepsError` variant,
a `tracing` field, or any other diagnostic/log-visible text cannot leak an
unredacted URL (including embedded credentials) without a deliberate, visible
type-system bypass — replacing today's convention of "remember to call
`url_for_tracing()`" with a structural guarantee that holds even when a
call site's author has never heard of `#767`.

### Out of Scope

- Re-fixing the concrete leak `#775` already closed — this spec is about the
  structural boundary only, not a new instance of leaked credentials.
- Any change to what counts as "sensitive" in a URL (userinfo, query string,
  fragment) — that classification already exists in `url_for_tracing()`/
  `redact_userinfo()` (`crates/deps-core/src/net_policy.rs`) and is not being
  revisited here.
- Redaction of secrets that do not travel through a URL (e.g. bare `GITHUB_TOKEN`/
  `GITLAB_TOKEN` values already handled by `Redacted<T>`/`expose_secret()` per
  `crates/deps-core/src/secret.rs`) — out of scope unless the chosen design
  naturally unifies the two (see Open Questions).

## 2. User Stories

### US-001: New ecosystem crate cannot introduce a URL leak by omission

AS A contributor adding the 15th ecosystem crate (or a new error path to an
existing one)
I WANT the compiler to refuse to build code that puts a raw, un-redacted URL into
a `DepsError` variant or a `tracing` log field
SO THAT a credential leak requires an explicit, reviewable act (e.g. calling an
`.expose()`-style escape hatch) rather than a missed `url_for_tracing()` call that
review has to catch by inspection.

**Acceptance criteria:**
```
GIVEN a new `DepsError`-returning function in any ecosystem crate that has a URL
  value in scope
WHEN the author writes it into a `DepsError` variant field that is later
  interpolated into `Display`/`Debug`/a `tracing::warn!`/`debug!` call
THEN the code does not compile unless the URL has already been converted to the
  redacted representation (or the raw value is never reachable from the variant's
  field type in the first place)
```

### US-002: Existing redaction call sites migrate without behavior change

AS A maintainer of `deps-core` and the ecosystem crates
I WANT the 44 existing `url_for_tracing()` call sites to be expressible through
the new chokepoint with no change in the redacted text they already produce
SO THAT the migration is a mechanical, low-risk refactor rather than a second
security-sensitive rewrite of redaction logic.

**Acceptance criteria:**
```
GIVEN the existing regression tests added by #775 (Display/Debug of DepsError,
  net_policy blocked-host/invalid-url logs, per-ecosystem independent leak-site
  tests)
WHEN the chokepoint is introduced and existing call sites migrated to it
THEN every one of those tests still passes unmodified (or is updated only to
  reflect the new type being asserted on, not a change in redacted output)
```

### US-003: Reviewer can audit "is this URL redacted?" without reading call-site logic

AS A code reviewer on a PR that touches error handling or logging in an
ecosystem crate
I WANT the type of a URL-bearing field/parameter to tell me on its own whether it
is safe to log
SO THAT I do not have to trace every call site back to confirm a
`url_for_tracing()` call happened before deciding a PR is safe to merge — this is
exactly the review step that missed the two `deps-cargo` sites the first time.

**Acceptance criteria:**
```
GIVEN a PR diff that adds or modifies a `tracing::warn!`/`debug!` call site or a
  `DepsError` variant construction
WHEN the reviewer inspects the type of the value being logged/stored
THEN the type alone (not the surrounding function body) establishes whether the
  value is redaction-safe
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a URL-bearing value is stored in a `DepsError` variant field that is exposed through `Display` or `Debug` THE SYSTEM SHALL make the raw, unredacted string unreachable from that field's type without an explicit, named escape hatch | must |
| FR-002 | WHEN an ecosystem crate logs a URL via `tracing::warn!`/`debug!`/`info!` THE SYSTEM SHALL route the value through the same chokepoint used for `DepsError` variants, rather than a second, independent redaction path | must |
| FR-003 | WHEN the chokepoint is introduced THE SYSTEM SHALL preserve the existing redaction semantics of `url_for_tracing()`/`redact_userinfo()` (query string, fragment, and userinfo handling, including the npm-scoped-package-name false-positive fix from #767 M1) byte-for-byte for already-covered inputs | must |
| FR-004 | WHEN a new ecosystem crate or `DepsError` variant is added after this feature ships THE SYSTEM SHALL require no additional manual redaction discipline beyond using the chokepoint type in the field/parameter signature | must |
| FR-005 | WHEN the 44 existing call sites (`crates/deps-core/src/{error.rs,cache.rs,github.rs,net_policy.rs,osv/mod.rs,deps_dev/mod.rs}` and the six ecosystem crates' `config.rs`/`parser.rs`/`sparse.rs`/`registry.rs`) are migrated THE SYSTEM SHALL leave no remaining direct `url_for_tracing()` call whose sole purpose duplicates the chokepoint's own guarantee — see Open Questions for whether `url_for_tracing()` itself is deprecated, kept as the chokepoint's internal implementation, or something else | should |
| FR-006 | WHEN `net_policy.rs`'s `validate_index_url` `BlockedHost` log and `deps-maven/registry.rs`'s `get_metadata` fallback-loop logs are revisited as part of this migration THE SYSTEM SHALL express them through the chokepoint type, even though both are already redacted today, so they benefit from the same compile-time guarantee as every other site instead of relying on the discipline that already fixed them once | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | The chokepoint must make it structurally impossible for a `DepsError`'s `Display`/`Debug` output to contain an unredacted URL for any variant that carries one — no code path (including a `{source}`-forwarded `reqwest::Error`) may re-introduce the raw value |
| NFR-002 | Maintainability | Migrating the 44 existing call sites must not require touching `crates/deps-lsp` (the handler layer only consumes `DepsError`'s `Display`, per `.claude/rules` architecture notes) |
| NFR-003 | Compatibility | `unsafe_code = "forbid"` (workspace-level) rules out any `unsafe`-based enforcement; the guarantee must come from ordinary type/visibility rules (private fields, no `AsRef<str>`/`Deref<Target = str>` exposing the raw value, etc.) |
| NFR-004 | Testability | The chokepoint type itself must have unit tests proving the raw value is unreachable through its public API (not just that redaction "usually" happens) |
| NFR-005 | Performance | Redaction already happens on error/cold paths only (never on the hover/completion hot path per `crates/deps-lsp`'s non-blocking handler rule) — the chokepoint must not add allocation or parsing cost to any hot path |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Outbound-URL-in-error-context | Any URL value that can end up in `DepsError`'s `Display`/`Debug`, a `tracing::warn!`/`debug!` field, an `InvalidEntry`-shaped struct, or hover-visible text derived from a registry/index URL | raw string form (never exposed once wrapped), redacted string form (query string/fragment/userinfo stripped per existing `url_for_tracing`/`redact_userinfo` rules) |
| Redaction chokepoint type (design TBD — see Open Questions) | The structural boundary this spec requires; exact shape is an implementation decision, not fixed here | construction point (where a raw string becomes the wrapped/redacted form), the only public read accessor being redaction-safe (`Display`/`AsRef<str>` on the *redacted* text only) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A `reqwest::Error` wrapped inside a `DepsError` variant still carries its own internal URL (reqwest's `Display` appends `" for url (...)"`) | The chokepoint's guarantee must hold even through `{source}` forwarding — `reqwest::Error::without_url()` (already applied by #775 at `RegistryError`-wrapping sites) must remain applied, or be structurally guaranteed by the same boundary, not left as a second manual discipline |
| A URL value that is not actually a URL (e.g. `RegistryError`'s `package` field sometimes holding a real package name, per `error.rs`'s existing doc comment) | The chokepoint must remain a no-op for non-URL-shaped text, exactly as `url_for_tracing()` is today (verified: it does not mangle `@types/node`-style scoped package names — the M1 false-positive this project already root-caused) |
| A future ecosystem crate needs the raw URL for something legitimate other than logging (e.g. actually issuing the HTTP request) | The chokepoint applies only to the error/log/diagnostic-output path; it must not block or complicate the existing, unredacted use of the URL for making the request itself |
| Debug builds / test code that intentionally wants to assert on the raw value | An explicit, clearly-named escape hatch (e.g. `#[cfg(test)]`-only accessor, or an admitted `.expose_raw()`-style method mirroring `Redacted<T>::expose_secret()`'s naming convention) must exist so tests can still verify what was redacted, without that same accessor being reachable from production call sites |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Ratio of URL-in-error/log call sites expressed through the chokepoint type vs. relying on a manual `url_for_tracing()` call | 100% of the 44 identified sites, plus every new site added after this ships |
| SC-002 | Existing `#775` regression test suite (Display/Debug redaction, net_policy blocked-host/invalid-url tests, per-ecosystem leak-site tests) | passes unmodified in behavior after migration |
| SC-003 | A reviewer can determine "is this URL redaction-safe?" from the type signature alone, without reading the function body | demonstrated by at least one new test/example showing a would-be leak fails to compile rather than requiring a manual catch in review |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing code patterns in `deps-core::net_policy` and `deps-core::error` for redaction semantics
- Run the full check suite (`fmt`, `clippy -D warnings`, `nextest`, rustdoc gate) before any PR
- Preserve `#775`'s existing regression tests; only touch their assertions where the type under test genuinely changed

### Ask First
- Deprecating or removing the public `url_for_tracing()`/`redact_userinfo()` free functions, since 44 existing call sites depend on them today
- Any change to `DepsError`'s public variant shapes (field types), since `DepsError` is consumed outside `deps-core` by every ecosystem crate and by `deps-lsp`
- Extending the chokepoint to also cover non-URL secrets (`Redacted<T>`) rather than staying URL-scoped

### Never
- Reintroduce a code path where a raw URL reaches `Display`/`Debug`/a `tracing` macro without going through the chokepoint
- Use `unsafe` to implement the guarantee (workspace-level `unsafe_code = "forbid"`)
- Weaken or bypass the existing redaction rules (query string/fragment/userinfo stripping, scoped-package-name no-op) while migrating call sites to the new type

## 9. Design Decisions

All six open questions below were resolved 2026-09-10 (Andrei G.) before handoff to implementation. No `[NEEDS CLARIFICATION]` items remain.

- **Newtype over strengthened `Display`.** Chosen: a `RedactedUrl` newtype (per `#767`'s original suggested-fix sketch), not a strengthened `DepsError::Display`/`Debug`. Roughly half of the 44 sites are bare `tracing::warn!`/`debug!` calls in ecosystem crates that never construct a `DepsError` at all (`config.rs`/`sparse.rs` parsing warnings, `net_policy.rs` blocked-host logs); only a type that can appear in a field/parameter signature anywhere — not just inside `DepsError` variants — satisfies FR-002 and US-003's "type alone establishes safety" requirement for those sites.
- **Location: `deps-core::net_policy`.** `RedactedUrl` lives next to `url_for_tracing`/`redact_userinfo`/`validate_index_url`, which already own the redaction ruleset (query string/fragment/userinfo stripping, the scoped-package-name no-op). It does **not** merge with `Redacted<T>` in `deps-core::secret` — the Agent Boundaries section flags that merge as "Ask First," and a URL is not itself a secret (it sometimes carries one), so keeping the two mechanisms separate is the conservative choice per that boundary.
- **Eager construction, raw value never stored.** `RedactedUrl::new(raw: &str)` calls `url_for_tracing`/`redact_userinfo` immediately in the constructor and stores only the resulting redacted `String`; the raw value is never retained inside the type, not even transiently. This satisfies NFR-001's "not retained" bar (stronger than "not exposed") and makes FR-001 ("raw string unreachable from the field's type") true by construction rather than by API discipline.
- **No raw-value escape hatch.** Because `RedactedUrl` never stores the raw value, there is nothing for an `expose_url()`-style accessor to return — the type's only public read surface (`Display`/`AsRef<str>`) is the redacted text, which is already the safe value to log or test against. The one legitimate consumer of the *raw* URL — the code path that actually issues the HTTP request — never constructs a `RedactedUrl` in the first place; it keeps working with its own `String`/`reqwest::Url` value, entirely independent of any `RedactedUrl` built from the same source for error/log purposes. NFR-004's "unit tests proving the raw value is unreachable through its public API" is satisfied trivially: no accessor exists that could return it.
- **`reqwest::Error::without_url()` subsumed into the chokepoint.** `DepsError::RegistryError`'s `source` field changes from `reqwest::Error` to a thin wrapper (e.g. `SanitizedRegistryError`) whose only constructor (`From<reqwest::Error>`) calls `.without_url()` unconditionally before storing the error; `Display`/`Debug`/`std::error::Error` forward through to the sanitized value. This is a change to a public `DepsError` variant's field type — flagged "Ask First" in Agent Boundaries — confirmed 2026-09-10. It closes the `{source}`-forwarding gap NFR-001 calls out (a wrapped `reqwest::Error`'s own `Display` re-embedding the raw URL) structurally instead of relying on `.without_url()` being called correctly at each of `RegistryError`'s construction sites. Ecosystem crates that construct `DepsError::RegistryError { package, source }` today pass `source.into()` (or rely on `?`/`From` conversion) instead of the bare `reqwest::Error`.
- **Staged rollout, not one PR.** PR 1 (this issue, `#789`) introduces `RedactedUrl` + `SanitizedRegistryError` in `deps-core` and migrates every `deps-core`-internal call site (`error.rs`, `cache.rs`, `github.rs`, `net_policy.rs`, `osv/mod.rs`, `deps_dev/mod.rs`) — the highest-leverage sites, since `DepsError` itself is consumed by every ecosystem crate and `deps-lsp`. Follow-up PRs (one filed as a tracking checklist item, not sub-issues) mechanically migrate the six ecosystem crates' `config.rs`/`parser.rs`/`sparse.rs`/`registry.rs` sites, mirroring how `#775` itself was reviewed incrementally. `url_for_tracing()`/`redact_userinfo()` stay public (not deprecated) — per Agent Boundaries' "Ask First" on deprecating them — since ecosystem crates still call them directly until their migration PR lands; `RedactedUrl`'s constructor uses them internally. SC-001's "100% of the 44 sites" target is met across the full staged sequence, not necessarily by PR 1 alone.

## 10. See Also

- [[constitution]] — project principles (not yet created)
- [[MOC-specs]] — all specifications
- [[053-ecosystem-sealing-inversion-decision-record/spec|Ecosystem sealing inversion decision record]] — another recent spec-as-decision-record on a structural/type-system boundary question in this codebase
- `crates/deps-core/src/error.rs` — `DepsError`, its four redacting `Display` helper functions, hand-written `Debug`
- `crates/deps-core/src/net_policy.rs` — `url_for_tracing()`, `redact_userinfo()`, `validate_index_url()`
- `crates/deps-core/src/secret.rs` — `Redacted<T>`/`expose_secret()`, the project's existing convention for a "type makes the unsafe access visible" secret boundary
- GitHub `#767` — original leak finding and suggested-fix design sketch (`RedactedUrl`/`TracingSafeUrl` newtype)
- GitHub `#775` — the PR that fixed the concrete leak and explicitly named this structural-chokepoint gap as an unfiled follow-up

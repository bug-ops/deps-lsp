---
aliases:
  - Credential Redaction Hardening
  - redact_userinfo Coverage Gaps
tags:
  - sdd
  - spec
  - security
  - deps-core
  - deps-cargo
  - deps-npm
  - deps-pypi
created: 2026-09-03
status: shipped
related:
  - "[[constitution]]"
  - "[[023-cargo-custom-registries/spec|Cargo custom/private registry & source-replacement resolution]]"
  - "[[032-npm-npmrc-registry-support/spec|npm .npmrc custom/private registry support]]"
  - "[[033-pypi-private-index-support/spec|PyPI private/custom index resolution]]"
---

# Feature: Redact `user:pass@` Credentials from Registry-Index Logs and Errors

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Status**: Shipped in two stages — PR #529 (issue #522), PR #540 (issue #536)
> **Priority**: P2 (security — cleartext credential disclosure via logs/error text)
> **Type**: security/hardening

Retroactive spec, written after ship per the project's spec-coverage policy — this documents already-implemented, already-merged behavior rather than driving new implementation. Filed as one spec covering both stages, following the project's convention for a single security fix that shipped as a closed follow-up pair (see [[024-net-policy-dns-rebinding/spec|024]]).

## 1. Overview

### Problem Statement

`deps-npm`'s `.npmrc` config resolver logged and retained the raw registry
index URL — including any literal `user:pass@` credential — when
`validate_index_url` rejected it. The module's own security-model doc only
covered the `${VAR}`-expansion leak case, not a credential written literally
in the raw value. `deps-pypi` already redacted this on its happy path via a
local `redact_userinfo` helper, but the fix had never been ported to
`deps-npm`; neither crate redacted the `InvalidUrl` (unparseable-URL) error
variant, which embeds the raw string in its `Display` regardless of the
parseable-case redaction (PR #529, issue #522).

A second, narrower leak channel surfaced immediately after: a Cargo
`registry-index` literal carrying `user:pass@` credentials that fails
`RegistryIndex::new` (e.g. `UserInfoPresent`) falls through to
`.cargo/config.toml` alias resolution in `resolve_alternate_registries`. When
that "alias" then failed to resolve, or collided with another such value on
the same `CARGO_REGISTRIES_*_INDEX` env-var name, the raw credential-bearing
value was logged in cleartext via `tracing::warn!` — neither call site was
covered by #529's redaction, which only applied to `validate_index_url`'s own
error type. This also surfaced a gap in `redact_userinfo` itself: a
schemeless `user:pass@host` literal (no `://`) parses successfully as an
opaque-scheme URL rather than failing `Url::parse` outright, so it bypassed
the unparseable-value fallback entirely and leaked unredacted through both
fixed call sites (PR #540, issue #536).

### Goal (shipped)

**Stage 1 (#529 / issue #522):**
- `redact_userinfo` promoted to `deps_core::net_policy` (previously a
  `deps-pypi`-local helper) and applied inside `validate_index_url` itself,
  at the single shared construction site for both the userinfo-rejected and
  unparseable-URL error variants — closing the leak for `deps-cargo`,
  `deps-npm`, and `deps-pypi` at once with no per-ecosystem call-site
  duplication.

**Stage 2 (#540 / issue #536):**
- `crates/deps-cargo/src/parser.rs`: redact the alias value before the
  unresolved-alias `tracing::warn!` in `resolve_alternate_registries`.
- `crates/deps-cargo/src/config.rs`: redact each entry in the alias list
  before the env-var-collision `tracing::warn!` in `resolve_registries`.
- `crates/deps-core/src/net_policy.rs`: fix `redact_userinfo`'s fallback to
  also handle a schemeless literal (previously required `://` to trigger the
  parse-independent scan) — this transitively fixes the same class of
  exposure in `deps-npm`/`deps-pypi`'s `InvalidEntry.raw`, which share this
  helper.
- `crates/deps-core/src/parser.rs`: doc-comment noting
  `DependencySource::CustomRegistry::url` is not redacted (latent, nothing
  currently renders it).

### Out of Scope

- `DependencySource::CustomRegistry::url` redaction — documented as a latent
  gap (nothing currently renders it), not fixed in either stage.
- Any change to how credentials are used for actual authenticated requests —
  both stages are about log/error-text hygiene, not auth wiring.

## 2. User Stories

### US-001: Rejected registry-index URL never logs its credential

AS A developer with a `user:pass@` credential in a registry-index value
(Cargo, npm, or PyPI) that fails validation
I WANT the logged/returned error text to redact the credential
SO THAT the credential doesn't end up in log files, CI output, or error
messages shown in the editor

**Acceptance criteria (verified shipped):**
```
GIVEN a registry-index value "https://user:hunter2@registry.example/simple"
  that fails validate_index_url (userinfo-rejected or unparseable)
WHEN the resulting error/log text is produced
THEN it contains "user:***@registry.example" or equivalent redaction,
  never the raw password, across deps-cargo, deps-npm, deps-pypi
```

### US-002: Cargo alias-fallback WARN logs never leak a credential

AS A developer with a `registry-index` literal carrying `user:pass@` that
falls through to `.cargo/config.toml` alias resolution
I WANT the unresolved-alias and env-var-collision WARN logs to redact the
credential
SO THAT the alias-fallback path doesn't reopen the leak #529 closed for the
direct-validation path

**Acceptance criteria (verified shipped):**
```
GIVEN registry-index = "sparse+https://user:pass@index.crates.io/" with an
  unresolvable alias
WHEN resolve_alternate_registries logs the WARN
THEN the log output does not contain the raw credential

GIVEN two registry-index values differing only in userinfo, colliding on the
  same CARGO_REGISTRIES_*_INDEX env-var name
WHEN resolve_registries logs the collision WARN
THEN neither raw credential appears in the log output
```

### US-003: `redact_userinfo` redacts schemeless literals

AS A maintainer of `deps-core`'s `net_policy` module
I WANT `redact_userinfo` to redact a schemeless `user:pass@host` literal
(no `://`), not only URLs with an explicit scheme
SO THAT every call site sharing this helper (`deps-cargo`, `deps-npm`,
`deps-pypi`) is covered, not just the ones that happen to pass a
scheme-qualified string

**Acceptance criteria (verified shipped):**
```
GIVEN the literal "user:hunter2@registry.example/simple" (no "://")
WHEN redact_userinfo is called
THEN the returned string has the credential redacted, not passed through
  unparsed (previously: parsed as an opaque-scheme URL and bypassed
  redaction entirely)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `deps_core::net_policy::redact_userinfo` SHALL be the single shared implementation used by `deps-cargo`, `deps-npm`, and `deps-pypi` | must |
| FR-002 | `validate_index_url` SHALL apply `redact_userinfo` to the raw value before it is embedded in either the userinfo-rejected or unparseable-URL (`InvalidUrl`) error variant | must |
| FR-003 | `deps-cargo`'s `resolve_alternate_registries` SHALL redact the alias value before its unresolved-alias `tracing::warn!` | must |
| FR-004 | `deps-cargo`'s `resolve_registries` SHALL redact each colliding alias entry before its env-var-collision `tracing::warn!` | must |
| FR-005 | `redact_userinfo` SHALL redact a schemeless `user:pass@host` literal, not only scheme-qualified URLs | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No `user:pass@` credential reaches a log line, `Display` output, or error message in cleartext across any of the three ecosystems sharing `redact_userinfo` |
| NFR-002 | Consistency | One shared `deps_core::net_policy::redact_userinfo` implementation, no per-ecosystem duplication of the redaction logic |
| NFR-003 | Regression safety | New regression tests fail against pre-fix code and pass post-fix, for both the raw-field and the reason/error/`Display` leak channel, in both the parseable-but-rejected and unparseable-URL cases |

## 5. Data Model

No new entities. Both stages harden existing error/log construction sites.

| Entity | Description | Change |
|--------|-------------|--------|
| `redact_userinfo` (existing, promoted in stage 1) | Redacts `user:pass@` from a URL-shaped string | Promoted from `deps-pypi`-local to `deps_core::net_policy`; stage 2 fixes its schemeless-literal fallback |
| `validate_index_url` (existing) | Shared index-URL validation | Stage 1: applies `redact_userinfo` to both error variants at the single construction site |
| `resolve_alternate_registries` (existing, `deps-cargo`) | `.cargo/config.toml` alias resolution | Stage 2: redacts alias value before unresolved-alias WARN |
| `resolve_registries` (existing, `deps-cargo`) | Env-var-driven registry resolution | Stage 2: redacts colliding alias entries before collision WARN |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior (shipped) |
|----------|-------------------|
| Scheme-qualified URL with `user:pass@`, fails validation | Redacted in both the rejected-field and `Display`/error-text channel (stage 1) |
| Unparseable URL (e.g. invalid port) carrying `user:pass@` | Redacted via the unparseable-value fallback (stage 1) |
| Schemeless `user:pass@host` literal | Redacted — previously bypassed redaction by parsing as an opaque-scheme URL (stage 2 fix) |
| Cargo alias unresolved after falling through from a rejected `registry-index` | WARN log redacted (stage 2) |
| Two Cargo `registry-index` values colliding on one env-var name, differing only in userinfo | WARN log redacted for both entries (stage 2) |
| `DependencySource::CustomRegistry::url` | Not redacted — documented latent gap, nothing currently renders it |

## 7. Success Criteria

| ID | Metric | Target (verified shipped) |
|----|--------|--------|
| SC-001 | Regression tests across `deps-core`, `deps-npm`, `deps-pypi`, `deps-cargo` covering both leak channels for both rejection cases | Pass — stage 1, 3646 tests total |
| SC-002 | Regression tests reproducing the alias-fallback and env-var-collision WARN leaks | Pass — stage 2, 3763 tests total, fail-before/pass-after verified during review |
| SC-003 | `redact_userinfo` schemeless-literal fix transitively closes the same class of exposure in `deps-npm`/`deps-pypi`'s `InvalidEntry.raw` | Confirmed — shared helper, no separate call-site fix needed |
| SC-004 | Full CI suite green for both stages | Pass — fmt/clippy/nextest/rustdoc gates clean |

## 8. Agent Boundaries

### Always (without asking)
- Route any new credential-bearing raw value through
  `deps_core::net_policy::redact_userinfo` before it reaches a log line,
  error `Display`, or diagnostic text.
- When adding a redaction call site, add both a raw-field test and a
  `Display`/error-text test — stage 1's gap (redacting the field but not the
  `Display` impl) is the exact failure mode to avoid.

### Ask First
- Adding a new opaque-scheme or scheme-less URL shape to any ecosystem's
  config parsing — verify it against `redact_userinfo`'s schemeless-literal
  handling first, per stage 2's finding.

### Never
- Log or return a raw registry-index/alias value without passing it through
  `redact_userinfo` first, in `deps-core`, `deps-cargo`, `deps-npm`, or
  `deps-pypi`.

## 9. Open Questions

None — implemented and merged in both stages.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[023-cargo-custom-registries/spec|Cargo custom/private registry & source-replacement resolution]] — introduced the alias-resolution path stage 2 hardens
- [[032-npm-npmrc-registry-support/spec|npm .npmrc custom/private registry support]] — one of the three ecosystems sharing `redact_userinfo`
- [[033-pypi-private-index-support/spec|PyPI private/custom index resolution]] — originated the local `redact_userinfo` helper promoted in stage 1
- `crates/deps-core/src/net_policy.rs` — `redact_userinfo`, `validate_index_url`
- `crates/deps-cargo/src/parser.rs`, `crates/deps-cargo/src/config.rs` — stage 2's redacted WARN sites
- Issue #522, PR #529 (commit `f8831d97`); issue #536, PR #540 (commit `a7859288`)

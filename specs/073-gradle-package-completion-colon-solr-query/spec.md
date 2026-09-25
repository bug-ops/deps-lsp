---
aliases:
  - Gradle/Maven colon-prefix completion 400
  - Solr field-query completion fix
tags:
  - sdd
  - spec
  - bug
  - deps-gradle
  - deps-maven
  - deps-core
created: 2026-09-25
status: draft
related:
  - "[[constitution]]"
  - "[[071-typosquat-similarity-diagnostic/spec]]"
---

# Feature: Gradle/Maven Package completion for a "group:partial-artifact" prefix returns 0 results (Maven Central Solr rejects the raw colon)

> [!info] Metadata
> **Author**: continuous-improvement live-testing cycle (Andrei G.)
> **Branch**: none yet — spec precedes implementation branch

## 1. Overview

### Problem Statement

Gradle's `Package`-completion arm resolves a partial dependency coordinate (e.g.
`com.google.guava:gua`, typed inside `implementation("com.google.guava:gua")`) by forwarding the
raw prefix string, unmodified, as `search.maven.org`'s Solr `q` query parameter
(`crates/deps-maven/src/registry.rs::search_url`). Maven Central's `solrsearch` endpoint parses an
unescaped `field:value`-shaped colon as a Lucene field-query. Since `com.google.guava` is not a
valid Solr field name on that endpoint, Solr returns `HTTP 400 Bad Request`. The error is caught by
`deps_core::completion::complete_package_names_generic` and silently converted into an empty
completion list — no diagnostic, no fallback, no log visible to the end user.

This is not a hypothetical: PR #1449 ("scope Package completion to recognized dependency call
shapes", merged) documents `implementation("com.google.guava:gua")` in
`.local/testing/playbooks/gradle.md` as the canonical example that *must* still trigger `Package`
completion — #1449 correctly routes this shape to the `Package` arm. The pre-existing, unrelated
`search_url` construction is what silently breaks it once routed there. The bug predates #1449; it
was simply unreachable/invisible before that fix stopped misrouting real dependency coordinates
elsewhere.

### Goal

A Gradle `Package`-completion prefix containing a `group:partial-artifact` coordinate (0 or 1
embedded colons — the exact shape `detect_dsl_context`'s `Package` arm admits) returns the same real
completion matches a correctly-formed Solr field query (`g:<group> AND a:<artifact-prefix>*`) proves
are available, instead of silently returning zero results.

### Out of Scope

- Any change to the `detect_dsl_context`/`GradleCompletionContext::Package` colon-count routing
  heuristic itself (already correct per #1447/#1449) — this spec only concerns what happens to a
  prefix *after* it is correctly routed to the `Package` arm.
- Maven's own `pom.xml` completion path (`MavenEcosystem::complete_package_names_for_field`) — see
  Section 6, confirmed not affected by this bug in normal usage (verified by reading
  `crates/deps-maven/src/ecosystem.rs`, not merely assumed).
- Any other ecosystem's Package-completion arm (npm, PyPI, Go, etc.) — none of them construct a
  colon-joined `group:artifact`-shaped completion prefix; this is specific to Maven-coordinate
  registries (Maven Central via Gradle).
- Non-Solr Maven registry operations (`maven-metadata.xml` version fetching, hover, diagnostics) —
  unaffected; only the Solr `search` path is broken.
- Google Maven / Gradle Plugin Portal search (`search.maven.org` is Maven Central-specific; the
  other two bases are not searched via Solr at all in this codebase).

## 2. User Stories

### US-001: Gradle dependency-coordinate completion works past the group segment

AS A developer editing a `build.gradle.kts`/`build.gradle` file
I WANT completion suggestions to keep working after I type the group id, a colon, and the start of
the artifact id (e.g. `implementation("com.google.guava:gua")`)
SO THAT I can find and select the correct artifact without needing to already know its exact name

**Acceptance criteria:**
```
GIVEN a build.gradle.kts file with `implementation("com.google.guava:gua")` and the cursor
  positioned immediately before the closing quote
WHEN the editor requests textDocument/completion at that position
THEN the response contains real Maven Central artifacts whose group is `com.google.guava` and whose
  artifact id starts with `gua` (e.g. `com.google.guava:guava-gwt`, `com.google.guava:guava-testlib`)
```

### US-002: The fix is not specific to one Gradle dependency-declaration call shape

AS A developer using any recognized Gradle dependency call shape (`implementation`,
`coreLibraryDesugaring`, `api`, `testImplementation`, etc.)
I WANT the same `group:partial-artifact` completion behavior regardless of which call/configuration
name I used
SO THAT the fix does not regress or special-case only the example call shape from the bug report

**Acceptance criteria:**
```
GIVEN a build.gradle.kts file with `coreLibraryDesugaring("com.google.guava:gua")` and the cursor
  positioned immediately before the closing quote
WHEN the editor requests textDocument/completion at that position
THEN the response contains the same real Maven Central completions as US-001, unaffected by which
  Gradle configuration function was used
```

### US-003: Colon-free and group-only prefixes are unaffected

AS A developer typing a dependency coordinate incrementally
I WANT completion to keep working correctly at every stage of typing (no colon yet, colon just
typed with nothing after it, colon plus partial artifact id)
SO THAT the fix for the "group:partial-artifact" shape does not regress the already-working
colon-free and group-with-trailing-colon cases

**Acceptance criteria:**
```
GIVEN a build.gradle.kts file with `implementation("gua")` (no colon) and the cursor before the
  closing quote
WHEN completion is requested
THEN the response is unchanged from current behavior (real matches against the raw prefix, e.g.
  `io.github.lizongying:gua64`)

GIVEN a build.gradle.kts file with `implementation("com.google.guava:")` (colon, no artifact
  prefix yet) and the cursor before the closing quote
WHEN completion is requested
THEN the response contains real Maven Central artifacts whose group is exactly `com.google.guava`
  (an empty artifact-id filter, i.e. `g:com.google.guava`), not zero results
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a Package-completion prefix contains exactly one `:` THE SYSTEM SHALL translate the prefix into a Solr field-query of the shape `g:<group> AND a:<artifact-prefix>*` before constructing the `solrsearch` request URL | must |
| FR-002 | WHEN a Package-completion prefix contains exactly one `:` and the substring after the colon is empty (e.g. `com.google.guava:`) THE SYSTEM SHALL still issue a valid Solr field-query scoped to the group (`g:<group>`) rather than treating the empty artifact segment as an error or an unfiltered wildcard | must |
| FR-003 | WHEN a Package-completion prefix contains zero colons THE SYSTEM SHALL preserve current behavior (the prefix is sent as free-text Solr `q`, unchanged) | must |
| FR-004 | WHEN the group or artifact-prefix segment of a colon-bearing completion prefix contains characters that are unsafe to interpolate into a Solr query (quotes, additional colons, Lucene special characters: `+ - && || ! ( ) { } [ ] ^ " ~ * ? : \ /`) THE SYSTEM SHALL escape or reject those characters so the constructed query is never itself a Lucene-syntax injection vector | must |
| FR-005 | WHEN the Solr field-query transform produces a request that Maven Central still rejects (e.g. a genuinely malformed group id) THE SYSTEM SHALL degrade to the existing empty-result behavior (no regression beyond current behavior), not a crash or unhandled panic | must |
| FR-006 | WHEN `search_url`'s cache key changes shape (colon-bearing vs. translated Solr-query form) THE SYSTEM SHALL still produce a stable, deterministic cache key for `HttpCache` so repeat completions for the same prefix continue to hit cache correctly | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | The fix must be verified against the live `search.maven.org` endpoint (per `.claude/rules/continuous-improvement.md`'s live-testing principle and the Registry Integration Gate), not only unit-tested with a mocked Solr response |
| NFR-002 | Security | The Solr-query construction must not introduce a Lucene-injection vector: an attacker-influenced or malformed group/artifact prefix must not let arbitrary Solr query syntax reach `search.maven.org` unescaped (see FR-004) |
| NFR-003 | Performance | The added query-transform logic (string parsing/escaping of a short prefix) must not introduce measurable completion latency; it must not add a network round trip beyond the existing single `search_with_retry` call |
| NFR-004 | Backward compatibility | Colon-free prefixes (US-003) and Maven's own `pom.xml` per-field completion path must be byte-for-byte behaviorally unchanged |
| NFR-005 | Cross-ecosystem consistency | Because `MavenCentralRegistry` is shared between `deps-maven` and `deps-gradle` (`deps-gradle`'s `registry()` returns the same `MavenCentralRegistry` type, per `registry.rs`'s `reports_yanked` doc comment), the fix must live in a place both consumers benefit from — not duplicated per-ecosystem-crate logic (see `.claude/rules/continuous-improvement.md`'s Cross-Ecosystem Consistency Testing principle and this project's stated aversion to a fix implemented for one consumer but not shared, `CLAUDE.md`'s "Cross-ecosystem consistency is a first-class design rule") |

## 5. Data Model

No new persistent data model. This is a pure request-construction change.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Completion prefix | The already-typed text `detect_dsl_context`'s `Package` arm extracts, spanning `group` or `group:partial-artifact` | Raw string, 0 or 1 `:` by construction (upstream-guaranteed shape) |
| Solr field-query | The transformed query string actually sent as `solrsearch`'s `q` parameter | `g:<group>` or `g:<group> AND a:<artifact-prefix>*`, Lucene-escaped |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Prefix has 0 colons (e.g. `gua`) | Unchanged: sent as free-text `q=gua` (FR-003) |
| Prefix has exactly 1 colon, non-empty both sides (e.g. `com.google.guava:gua`) | Translated to `g:com.google.guava AND a:gua*` (FR-001) |
| Prefix has exactly 1 colon, empty artifact segment (e.g. `com.google.guava:`) | Translated to `g:com.google.guava` alone (FR-002) |
| Prefix has exactly 1 colon, empty group segment (e.g. `:gua`) | `[NEEDS CLARIFICATION: does `detect_dsl_context` ever produce this shape in practice? If reachable, define behavior — likely fall back to free-text `q` or reject as invalid, since `g:` with an empty value is not a meaningful Solr filter]` |
| Group or artifact segment contains Lucene special characters (`"`, extra `:`, `*`, parens, etc.) | Escaped per Lucene query-string escaping rules, or the offending prefix is rejected and falls back to the pre-fix behavior (empty result) rather than sending unescaped syntax (FR-004) |
| Solr still returns non-200/malformed body after the fix (e.g. genuinely invalid coordinate, transient outage) | Existing `search_with_retry`/stale-cache-fallback/`recent_search_failures` machinery applies unchanged — this fix only changes the URL construction, not the retry/error-handling layer |
| `detect_dsl_context` produces a `Package`-range value with more than 1 colon (should not happen per current heuristic, but defense-in-depth) | `[NEEDS CLARIFICATION: should the transform defensively handle >1 colon (treat only the first as group/artifact separator, or fall back to free-text query), or is it acceptable to trust the 0-1-colon invariant documented at the `detect_dsl_context` call site and treat a 2+-colon input as an internal-invariant violation not worth guarding against here?]` |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live completion request for `implementation("com.google.guava:gua")` returns non-empty, correct results against the real `search.maven.org` endpoint | Pass (matches the `curl`-verified `numFound: 19` result set, e.g. includes `com.google.guava:guava-gwt`) |
| SC-002 | Existing colon-free completion behavior (`implementation("gua")`) | Unchanged, zero regressions in `deps-gradle`/`deps-maven` test suites |
| SC-003 | New unit tests covering `search_url`'s colon-bearing-prefix branch (0 colons, 1 colon w/ non-empty artifact, 1 colon w/ empty artifact, Lucene-special-character escaping) | All pass, added to `crates/deps-maven/src/registry.rs`'s existing `#[cfg(test)] mod tests` |
| SC-004 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo nextest run --workspace --all-features --no-fail-fast` | Pass |
| SC-005 | `.local/testing/playbooks/gradle.md`'s "Package completion call-shape gate (#1447, PR #1449)" scenario, re-run live | Now returns real completions instead of 0 items |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo nextest run -p deps-maven -p deps-gradle` after changes
- Follow the existing `search_url`/`metadata_urls` module conventions in `crates/deps-maven/src/registry.rs` (doc-comment density, `#[tracing::instrument]` usage, error redaction via `net_policy`/`redact` helpers)
- Live-verify the fix against the real `search.maven.org` endpoint before considering the fix complete (per the Registry Integration Gate in `.claude/rules/continuous-improvement.md`)
- Add/update the relevant row in `.local/testing/coverage.md` and `.local/testing/playbooks/gradle.md` per `.claude/rules/branching.md`'s "Before Creating a PR" checklist

### Ask First
- Introducing a new dependency for Lucene query escaping (a small hand-rolled escaper is likely sufficient and preferable per this project's "avoid excessive dependencies" MVP principle — confirm before adding one)
- Changing `search_url`'s signature in a way that affects `HttpCache`'s cache-key semantics beyond what FR-006 requires

### Never
- Touch `crates/deps-zed` (separate submodule/repo)
- Change the `detect_dsl_context`/`GradleCompletionContext::Package` colon-count routing heuristic (out of scope, already correct)
- Silently swallow a Lucene-injection-shaped prefix without either escaping or rejecting it (NFR-002)

## 9. Open Questions

- [NEEDS CLARIFICATION: Which layer should architecturally own the Solr-query-syntax transform — `deps-maven`'s `search_url`/`MavenCentralRegistry::search` (Maven-registry-specific Solr knowledge, recommended given NFR-005's shared-consumer requirement is satisfied automatically since both `deps-maven` and `deps-gradle` already funnel through the same `MavenCentralRegistry`), or should the colon-splitting happen earlier at the caller (`deps-core::completion::complete_package_names_generic` or `deps-gradle`'s `complete_package_names`) with a structured `(group, artifact_prefix)` argument passed down instead of a single string? The registry-owns-it approach requires no caller changes and keeps Solr syntax knowledge encapsulated in the one crate that talks to Solr; the caller-splits approach would give `deps-core`/`deps-gradle` type-level visibility into the two-part shape but requires touching the shared `Registry` trait's `search`/`search_raw` signature, which every other ecosystem's registry also implements.]
- [NEEDS CLARIFICATION: exact Lucene-escaping strategy for FR-004 — full Lucene special-character backslash-escaping of both group and artifact segments (safest, matches Solr's own documented escaping rules), or a narrower reject-if-any-special-character-present gate (simpler, matches this codebase's existing "reject rather than sanitize" pattern seen in `is_safe_maven_coordinate_segment`/`reject_credential_bearing_value`)? A real `groupId`/`artifactId` per Maven's coordinate grammar never legitimately contains Lucene special characters (they are restricted to `[A-Za-z0-9_.-]`-ish sets already validated elsewhere in this file, e.g. `maven_coordinate_path`), so a reject-based gate may be sufficient and simpler than general escaping — needs a decision during `/sdd plan`.]
- [NEEDS CLARIFICATION: should FR-002's `g:<group>`-only query (empty artifact segment) also be applied to the case where the *whole* prefix, pre-colon-split, would already have been considered "too short" by `is_valid_completion_prefix_len`'s existing minimum-length gate? i.e., does the minimum-length check apply to the raw prefix (pre-split) as it does today, or should it apply post-split to the group and/or artifact segment individually? Confirm during `/sdd plan` against `is_valid_completion_prefix_len`'s current semantics.]
- [NEEDS CLARIFICATION: is a `g:<empty>` (colon-first, e.g. `:gua`) prefix shape actually reachable from `detect_dsl_context`'s `Package` arm, or is it excluded upstream by construction? See Section 6's edge case.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[071-typosquat-similarity-diagnostic/spec]] — most recent prior spec touching the same `deps.dev`/Maven registry-search surface area
- `crates/deps-maven/src/registry.rs::search_url`, `MavenCentralRegistry::search` — root-cause location
- `crates/deps-gradle/src/ecosystem.rs::complete_package_names`, `detect_dsl_context` (colon-count routing, `GradleCompletionContext::Package`)
- `crates/deps-core/src/completion.rs::complete_package_names_generic` — shared caller that silently swallows the `HTTP 400` today
- `.local/testing/playbooks/gradle.md` — "Package completion call-shape gate (#1447, PR #1449)" playbook section documenting the exact reproduction shape
- PR #1449, issue #1447 — the prior fix that made this bug newly reachable/visible (not its cause)

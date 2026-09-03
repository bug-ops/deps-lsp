---
aliases:
  - GitHub Rate-Limit Actionable Diagnostic
  - FetchFailure Classifier
tags:
  - sdd
  - spec
  - bug
  - deps-core
  - deps-github-actions
  - deps-lsp
created: 2026-09-02
status: shipped
related:
  - "[[constitution]]"
  - "[[040-github-token-redaction-trusted-origin-pin/spec|GitHub auth token redaction and trusted-origin pinning]]"
---

# Feature: Surface an Actionable Rate-Limit Hint in Registry Diagnostics

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Status**: Shipped — PR #485 (issue #478)
> **Priority**: P1 (bug — misleading diagnostic under a common, easily-hit failure mode)
> **Type**: bug

Retroactive spec, written after ship per the project's spec-coverage policy — this documents already-implemented, already-merged behavior rather than driving new implementation.

## 1. Overview

### Problem Statement

Opening a manifest with GitHub-resolved dependencies (initially GitHub Actions
`uses:` steps, but the root cause is systemic across every ecosystem in
`deps-core`) under an unauthenticated GitHub API rate limit showed a generic
"Registry lookup failed... package status could not be determined" diagnostic
for every affected dependency — even though the server had already computed
the actionable remedy ("set `GITHUB_TOKEN`") and fired it once via a toast
notification.

Root cause: the per-dependency diagnostic carrier only tracked failed package
names (`HashSet<String>`), with no error detail attached, so the diagnostic
renderer always fell back to the generic text regardless of *why* the fetch
failed. Any non-not-found registry error, across any ecosystem, hit the same
generic fallback.

### Goal (shipped)

- `DepsError::RateLimited { message }` replaces a prior misuse of
  `DepsError::CacheError` as an ad hoc string carrier for rate-limit errors.
- A new `DepsError::fetch_failure() -> FetchFailure` classifier maps errors to
  `Actionable(String)`, `Transient`, or `NotAttempted`.
- The `fetch_failed` carrier is widened from `HashSet<String>` to
  `HashMap<String, FetchFailure>` in `deps-core` and `deps-lsp`, so the
  specific hint reaches the inline per-dependency diagnostic instead of only
  the one-shot toast.
- **Security-load-bearing invariant**: `Actionable` diagnostic text is
  produced *only* from `RateLimited`'s pre-vetted, canned message — never
  from `Display`/`to_string()` on any other error variant, since GitHub's raw
  rate-limit error body can embed the caller's public IP address.
- Fixed a regression caught during review: a source-collided dependency
  (`FetchFailure::NotAttempted`) was rendering a false "Unknown package"
  instead of the previous, correct generic fallback text.

### Out of Scope

- Automatically retrying or backing off on rate limit — this PR only
  improves the diagnostic text, not the retry/backoff strategy.
- Any change to how `GITHUB_TOKEN` itself is read, stored, or applied to
  requests — that is [[040-github-token-redaction-trusted-origin-pin/spec|the
  companion hardening PR (#487)]] this issue's security review surfaced.

## 2. User Stories

### US-001: Rate-limited GitHub fetch surfaces the actionable remedy inline

AS A developer with GitHub Actions `uses:` pins in `.github/workflows/*.yml`
and no `GITHUB_TOKEN` configured
I WANT the per-dependency diagnostic to tell me to set `GITHUB_TOKEN` when the
unauthenticated rate limit is the actual cause
SO THAT I don't mistake a rate limit for a broken/unknown package and waste
time investigating the wrong thing

**Acceptance criteria (verified shipped):**
```
GIVEN a workflow file with several `uses:` steps
  AND the GitHub tags API returns a 403 rate-limit response for every one
WHEN diagnostics are computed
THEN each affected dependency's diagnostic carries the actionable message
  ("set GITHUB_TOKEN to increase the rate limit"), not the generic
  "package status could not be determined" fallback
```

### US-002: Non-rate-limit errors never leak raw error text

AS A maintainer of `deps-core`
I WANT every error variant other than `RateLimited` (and the pre-vetted
`ChainResolutionHalted`) to classify as `FetchFailure::Transient`
SO THAT an arbitrary upstream error body — which could embed request
metadata such as the caller's IP — never reaches the diagnostic UI verbatim

**Acceptance criteria (verified shipped):**
```
GIVEN any DepsError variant other than RateLimited/ChainResolutionHalted
WHEN fetch_failure() is called
THEN the result is FetchFailure::Transient
  (exhaustive classifier test over all non-RateLimited variants,
  crates/deps-core/src/error.rs)
```

### US-003: Source-collided dependencies keep the correct fallback text

AS A developer with a dependency whose source resolution was skipped (not
attempted, not failed)
I WANT the generic fallback text, not a false "Unknown package" claim
SO THAT the diagnostic doesn't misrepresent a skipped lookup as a
nonexistent package

**Acceptance criteria (verified shipped):**
```
GIVEN a dependency classified as FetchFailure::NotAttempted
WHEN its diagnostic is rendered
THEN it shows the previous generic fallback text, not "Unknown package"
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL represent a GitHub API rate-limit failure as `DepsError::RateLimited { message }` instead of `DepsError::CacheError` | must |
| FR-002 | THE SYSTEM SHALL provide `DepsError::fetch_failure() -> FetchFailure` classifying every variant into `Actionable(String)`, `Transient`, or `NotAttempted` | must |
| FR-003 | THE SYSTEM SHALL thread `FetchFailure` through the `fetch_failed: HashMap<String, FetchFailure>` carrier in `deps-core` and `deps-lsp`, replacing the prior `HashSet<String>` | must |
| FR-004 | THE SYSTEM SHALL NEVER construct `FetchFailure::Actionable` from `Display`/`to_string()` on any error variant other than `RateLimited`'s pre-vetted message (and `ChainResolutionHalted`'s fixed message) | must |
| FR-005 | THE SYSTEM SHALL render the generic fallback text (not "Unknown package") for `FetchFailure::NotAttempted` | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No upstream error body is ever surfaced verbatim in a diagnostic — closes a potential IP-address-disclosure channel via GitHub's raw rate-limit response |
| NFR-002 | Consistency | The fix is systemic in `deps-core`, so any ecosystem hitting a `RateLimited` error (not only GitHub Actions) benefits automatically |
| NFR-003 | Reliability | No additional network calls introduced — this is a classification/plumbing change over the existing error, not a new fetch |

## 5. Data Model

| Entity | Description | Change |
|--------|-------------|--------|
| `DepsError::RateLimited { message: String }` (new variant) | Carries a pre-vetted, IP-free rate-limit message | Replaces prior `CacheError`-as-string-carrier misuse |
| `FetchFailure` (new enum) | `Actionable(String)` \| `Transient` \| `NotAttempted` | New — classification result of `DepsError::fetch_failure()` |
| `fetch_failed` carrier (existing field, `deps-core`/`deps-lsp`) | Per-dependency map of failed fetches | Type widened `HashSet<String>` -> `HashMap<String, FetchFailure>` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior (shipped) |
|----------|-------------------|
| GitHub API 403 rate-limit response, no `GITHUB_TOKEN` set | `Actionable("set GITHUB_TOKEN to increase the rate limit")` surfaces inline |
| Any other registry error (network timeout, 5xx, malformed response) | `Transient` — generic fallback text, no raw error body leaked |
| Dependency whose source resolution collided/was skipped | `NotAttempted` — generic fallback text, not "Unknown package" |
| `ChainResolutionHalted` | `Actionable` with its own fixed, pre-vetted message — exempted from the "everything else is Transient" rule alongside `RateLimited` |

## 7. Success Criteria

| ID | Metric | Target (verified shipped) |
|----|--------|--------|
| SC-001 | Rate-limited GitHub Actions dependency shows the actionable hint inline | Pass — end-to-end trace test from `DepsError::RateLimited` through to the diagnostic carrier |
| SC-002 | Every non-`RateLimited`/non-`ChainResolutionHalted` variant classifies `Transient` | Pass — exhaustive classifier test |
| SC-003 | `NotAttempted` dependencies keep the correct fallback text | Pass — regression test added during review |
| SC-004 | Full CI suite green | Pass — 3510 tests, fmt/clippy/doc gates clean |

## 8. Agent Boundaries

### Always (without asking)
- Keep `FetchFailure::Actionable` construction restricted to pre-vetted,
  canned messages — never wire in `Display`/`to_string()` on an arbitrary
  error.

### Ask First
- Adding a new `Actionable` source beyond `RateLimited`/`ChainResolutionHalted`
  — must be reviewed for the same IP/metadata-leak risk this PR closed.

### Never
- Render raw upstream error bodies in a user-facing diagnostic.

## 9. Open Questions

None — implemented and merged.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[040-github-token-redaction-trusted-origin-pin/spec|GitHub auth token redaction and trusted-origin pinning]] — the security-hardening follow-up this issue's review surfaced
- `crates/deps-core/src/error.rs` — `DepsError::RateLimited`, `FetchFailure`, `fetch_failure()`
- `crates/deps-core/src/github.rs` — `DepsError::RateLimited` construction site
- Issue #478, PR #485 (commit `c3da3570`)

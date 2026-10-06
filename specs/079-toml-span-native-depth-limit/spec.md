---
aliases:
  - toml-span native depth limit
  - TOML nesting pre-scan reconciliation
tags:
  - sdd
  - spec
  - research
  - dependencies
  - deps-core
  - security/dos
created: 2026-10-06
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Reconcile the TOML nesting pre-scan with toml-span 0.7.2's native depth limit

> [!info] Metadata
> **Author**: rust-researcher (research session, 2026-10-06)
> **Branch**: N/A (research finding, no implementation branch)
> **Priority**: P4 (defense-in-depth is already in place; this is consistency and documentation debt)
> **Depends on**: the `toml-span` lock bump to 0.7.2, tracked separately as a dependency issue [NEEDS CLARIFICATION: issue number of the toml-span 0.7.2 lock-bump issue]

## 1. Overview

### Problem Statement

`deps-core` guards every untrusted-TOML parse with a hand-rolled, single-pass structural pre-scan,
`deps_core::parser::check_toml_nesting_depth`, bounded by `MAX_TOML_NESTING_DEPTH = 64` and exposed to
all ecosystems through the one shared entry point `parse_toml_checked` (introduced for #150 and #1403;
consumed by `deps-cargo`, `deps-pypi`, `deps-gradle` and `deps-cli`). The pre-scan exists because
`toml-span` 0.7.1's recursive-descent parser has no recursion limit: a deeply nested `[[[...]]]` array,
`{a={a=...}}` inline table, or dotted key/header can overflow the native thread stack and SIGABRT the
whole process before `toml_span::parse` returns. The constant's doc comment records this rationale and
the 0.7.1 stack bisection that sized it. `deps-lsp` additionally raises its tokio worker stacks to 8 MiB
(`WORKER_THREAD_STACK_SIZE`, `crates/deps-lsp/src/main.rs`) as a second layer.

`toml-span` 0.7.2 (released 2026-10-02; upstream PR `EmbarkStudios/toml-span#24`, "Avoid stack
overflow") adds a native limit, `MAX_NESTING_DEPTH = 128`, covering arrays, inline tables, dotted keys
and table headers, and reports it as a new `ErrorKind::ExceededDepthLimit` ("input exceeds the maximum
allowed nesting depth"). After the lock moves to 0.7.2 three things become true at once:

1. The pre-scan is no longer the only barrier against the SIGABRT class; it is a stricter second one
   (64 vs 128).
2. Several doc comments and test comments assert something that is no longer accurate ("`toml-span`
   0.7.1's recursive-descent parser has no recursion limit", "so `toml_span::parse` ... still
   stack-overflowed"), and the 64 / 220 / 305 bisection figures describe a parser version that is no
   longer the one in use.
3. A depth error can now originate from two layers (our pre-scan and upstream), and today only the
   first maps to the typed `CheckedTomlError::NestingTooDeep`; the second would surface as an opaque
   `CheckedTomlError::Syntax(toml_span::Error)`, so callers and diagnostics could not tell "too deep"
   from "malformed" without string-matching, which `CheckedTomlError` was introduced to avoid.

This is not a bug: today's behavior is safe on 0.7.1 and stays safe on 0.7.2. It is an open question
about what to keep, what to rewrite, and what to assert so a future regression is caught.

> [!info] Empirical evidence (2026-10-06)
> Scratch crate outside the repo, `toml-span =0.7.2`, debug build, parse on a **2 MiB-stack thread**:
>
> | Shape | Result |
> |-------|--------|
> | Arrays 64 and 127 deep | parses ok |
> | Arrays 129, 5000, 100000 deep | clean `ExceededDepthLimit`, no abort |
> | Inline tables `a={a={...}}` | error already at 64 levels (the limit also counts dotted-key length, so effective inline-table depth is about 64) |
> | Table headers `[a.a...]` | 127 ok, 129+ error |
>
> So the upstream guard protects against the SIGABRT class even without the pre-scan, with a limit twice
> as large as the pre-scan's.

### Goal

After the `toml-span` 0.7.2 lock bump lands, the codebase has one coherent, documented story for TOML
nesting protection: every layer's role is stated accurately, depth errors from either layer are
reported uniformly, and a test or fuzz target fails if the upstream guard is ever absent.

### Out of Scope

- Performing the `toml-span` lock/version bump itself (tracked as a separate dependency issue; this
  spec only constrains what must be true around it).
- Any change to the JSON (`MAX_JSON_NESTING_DEPTH`) or YAML (`MAX_YAML_NESTING_DEPTH`) guards beyond
  fixing a cross-reference in a shared doc comment.
- Changing `WORKER_THREAD_STACK_SIZE` (8 MiB) or other runtime stack configuration.
- Implementation design (how the variant is shaped, which tests are written); that belongs in `plan`.
- Edits under `crates/deps-zed` (separate repository).

> [!danger] Ordering constraint
> The pre-scan MUST remain in place, and its documentation MUST keep stating that 0.7.1 has no
> recursion limit, until the lock/MSRV bump to 0.7.2 has actually landed on `main`. Until then
> `Cargo.lock` pins 0.7.1 and the pre-scan is the only barrier. Documentation reconciliation and any
> pre-scan decision are bump-gated, not time-gated.

## 2. User Stories

### US-001: Accurate protection rationale
AS A maintainer reading `parser.rs` after the bump
I WANT the doc comments to describe which layer protects against what, for which `toml-span` versions
SO THAT I do not remove a still-needed guard, or keep a "bisected for 0.7.1" figure I believe is load-bearing when it is not.

**Acceptance criteria:**
```
GIVEN the toml-span 0.7.2 lock bump has merged
WHEN a maintainer reads MAX_TOML_NESTING_DEPTH, check_toml_nesting_depth and CheckedTomlError docs
THEN no doc states that toml-span has no recursion limit as a present-tense fact
AND the docs state that the pre-scan is a stricter policy/defense-in-depth bound relative to the upstream 128 limit
AND the 0.7.1 bisection figures are labeled historical
```

### US-002: Uniform depth diagnostics
AS A user (editor or deps-cli) with a pathologically nested TOML file
I WANT the same kind of "nesting too deep" message regardless of which layer rejected the file
SO THAT the error is not mistaken for a syntax error in my manifest.

**Acceptance criteria:**
```
GIVEN a TOML file nested deeper than 128 levels
WHEN it is parsed through parse_toml_checked
THEN the result is the depth-class CheckedTomlError, not Syntax

GIVEN a TOML file nested between 65 and 128 levels (arrays)
WHEN it is parsed through parse_toml_checked (pre-scan retained)
THEN the result is the same depth-class error, and the process does not abort
```

### US-003: Regression tripwire
AS A maintainer
I WANT a failing test or fuzz assertion if the upstream guard disappears (downgrade, yanked release, or upstream regression)
SO THAT removing or weakening our own pre-scan in the future cannot silently reintroduce the SIGABRT class.

**Acceptance criteria:**
```
GIVEN toml-span is resolved to a version without the native depth limit
WHEN the test suite runs
THEN at least one test fails and names the missing upstream guard
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHILE `Cargo.lock` resolves `toml-span` to a version without the native depth limit (0.7.1 and earlier), THE SYSTEM SHALL keep invoking `check_toml_nesting_depth` with `MAX_TOML_NESTING_DEPTH` before `toml_span::parse` on every untrusted-TOML path, and SHALL keep the existing 0.7.1 rationale in its docs. | must |
| FR-002 | WHEN `Cargo.lock` resolves `toml-span` to 0.7.2 or later, THE SYSTEM SHALL continue to route every untrusted-TOML parse (manifests, lock files, `deps-cli` config) through the single shared `parse_toml_checked` entry point. | must |
| FR-003 | WHEN `toml_span::parse` returns `ErrorKind::ExceededDepthLimit`, THE SYSTEM SHALL return a depth-class `CheckedTomlError` that callers can distinguish from `Syntax` without string matching. | must |
| FR-004 | WHERE a depth-class `CheckedTomlError` is produced by the upstream layer, THE SYSTEM SHALL NOT report a fabricated nesting-depth number, since upstream does not expose the reached depth. | must |
| FR-005 | THE SYSTEM SHALL present depth errors from the pre-scan and from upstream with the same user-visible category (and a message that names the limit in force) in `deps-lsp` diagnostics, `deps-cli` `ConfigError::Toml`, and `DepsError::ParseError` for lock files and manifests. | should |
| FR-006 | WHEN the lock bump to 0.7.2 has merged, THE SYSTEM SHALL update every doc or test comment that states or implies "toml-span has no recursion limit" or that attributes a stack overflow to `toml_span::parse` at depths the upstream guard now rejects: `MAX_TOML_NESTING_DEPTH`, `check_toml_nesting_depth`, `CheckedTomlError`, the `MAX_YAML_NESTING_DEPTH` cross-reference "as with `MAX_TOML_NESTING_DEPTH`", `deps-core/README.md`, `WORKER_THREAD_STACK_SIZE` doc in `deps-lsp/src/main.rs`, `deps-cli/src/config.rs`, and the regression-test comments in `deps-cargo` (`lockfile.rs`, `parser.rs`), `deps-gradle` (`parser/catalog.rs`) and `deps-pypi`. | must |
| FR-007 | WHEN the lock bump has merged, THE SYSTEM SHALL contain at least one test that calls `toml_span::parse` directly, on a thread with a stack no larger than 2 MiB, with input nested beyond 128 levels, and asserts `ErrorKind::ExceededDepthLimit` is returned. | must |
| FR-008 | WHERE the pre-scan is retained, THE SYSTEM SHALL keep its boundary tests at `MAX_TOML_NESTING_DEPTH` (arrays, inline tables, dotted keys, dotted headers) and SHALL add a test pinning the 65 to 128 band as rejected by our layer, so the policy gap between the two limits is explicit. | should |
| FR-009 | WHERE the pre-scan is removed (see OQ-1), THE SYSTEM SHALL first raise the workspace `toml-span` requirement floor so a resolver cannot select a version without the native limit, AND SHALL re-bisect worst-case mixed-shape stack usage at 128 levels on a 2 MiB stack in debug and release builds. | must |
| FR-010 | THE SYSTEM SHALL keep the fuzz target `fuzz/fuzz_targets/parse_toml_checked.rs` asserting no panic/abort for arbitrary UTF-8, and the seed corpus under `fuzz/seeds` SHALL include at least one input in the 65 to 128 band and one beyond 128. | should |
| FR-011 | WHEN user-visible behavior changes (for example the accepted depth range or error wording), THE SYSTEM SHALL record it in `CHANGELOG.md` `[Unreleased]` as a one-line entry with the PR link. | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | No input within the library's accepted range SHALL abort the process on a 2 MiB-stack thread, in either debug or release builds. |
| NFR-002 | Security | Error text surfaced through `redact_parse_error_for_log` paths SHALL remain free of attacker-controlled content; the upstream depth message is a fixed string and SHALL NOT be treated as needing a different redaction path. |
| NFR-003 | Consistency | The mapping SHALL live in `deps-core` (shared helper), never reimplemented per ecosystem crate, per the cross-ecosystem consistency rule. |
| NFR-004 | Type safety | The depth outcome SHALL be encoded as an enum variant (no stringly-typed discrimination, no sentinel depth value), and any `match` on `CheckedTomlError` SHALL stay exhaustive. |
| NFR-005 | Maintainability | Each protection layer's doc SHALL state its role (safety backstop vs policy bound) and the `toml-span` versions it assumes. |
| NFR-006 | Performance | The pre-scan is a single linear pass; retaining it SHALL NOT add measurable latency to hover/completion paths (those use cached state per the non-blocking handler rule). |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `MAX_TOML_NESTING_DEPTH` | Our policy/safety bound on bracket depth plus dotted-key/header segments | currently 64 |
| Upstream limit | `toml-span` 0.7.2 `MAX_NESTING_DEPTH` | 128; counts arrays, inline tables, dotted keys, headers; inline-table effective depth about 64 because dotted-key length is added |
| `CheckedTomlError` | Typed outcome of `parse_toml_checked` | `NestingTooDeep { depth }`, `Syntax(toml_span::Error)`; possible third depth-class source (OQ-2) |
| Layer matrix | Which layer rejects which input | see Section 6 |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Array nested 65 to 128 levels, pre-scan retained | Rejected by pre-scan as depth-class error; upstream would have accepted it |
| Array nested 65 to 128 levels, pre-scan removed (OQ-1) | Accepted and parsed; behavior change that FR-011 must record |
| Array nested beyond 128 levels, pre-scan removed | `ExceededDepthLimit` mapped to depth-class error (FR-003) |
| Inline table `{a={a=...}}` 64 levels | Pre-scan boundary (64) and upstream's effective inline-table limit (about 64) nearly coincide; exact off-by-one relationship is unverified |
| Mixed shapes (array of inline tables of dotted keys) near 128 | Per-level stack cost is shape-dependent; worst-case mix has not been measured on 0.7.2 |
| Lock still pinned at 0.7.1 | Pre-scan is the sole barrier; docs unchanged (FR-001) |
| Resolver picks 0.7.1 after a future `cargo update` / downgrade with floor still `"0.7"` | Canary test (FR-007) fails; with pre-scan retained, safety is still intact |
| Depth error from upstream carries no depth value | Variant carries no number (FR-004) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Doc and comment sites asserting "no recursion limit" for current `toml-span` after the bump | 0 |
| SC-002 | Inputs nested beyond 128 levels returning the depth-class error instead of `Syntax` through `parse_toml_checked` | 100% |
| SC-003 | Process aborts across the fuzz target and the regression suite on 2 MiB stack threads | 0 |
| SC-004 | Tests that fail when the resolved `toml-span` lacks the native limit | at least 1 |
| SC-005 | Ecosystem crates containing their own copy of nesting logic or depth-error mapping | 0 |

## 8. Agent Boundaries

### Always (without asking)
- Keep `check_toml_nesting_depth` in place until the 0.7.2 lock bump has merged on `main`.
- Verify claims about toml-span behavior with a live scratch-crate run against the pinned version, not by reading code alone.
- Route any TOML depth handling through `deps-core`'s shared helper.

### Ask First
- Removing the pre-scan, changing `MAX_TOML_NESTING_DEPTH`, or changing `WORKER_THREAD_STACK_SIZE`.
- Changing the shape of `CheckedTomlError` (a public type; breaking changes are allowed pre-1.0 but must be recorded in `CHANGELOG.md`).
- Raising the workspace `toml-span` requirement floor.

### Never
- Edit source code as part of the continuous-improvement research session that produced this spec.
- Add a catch-all `_ =>` arm when matching `ErrorKind` or `CheckedTomlError` to sidestep exhaustiveness.
- Fabricate a depth number for an error that upstream reports without one.
- Touch files under `crates/deps-zed`.

## 9. Open Questions

> [!question] Open items (8)
> Resolve before moving to `plan`.

- [NEEDS CLARIFICATION: OQ-1 Keep or remove the pre-scan after the bump? Research recommendation: keep it. It is a cheap single pass, its 64 bound is stricter than upstream's 128 and matches the corpus (deepest real bracket nesting 5, deepest dotted path 6), it mirrors the JSON and YAML guards, and it applies identically to every ecosystem. Reframe it as a policy bound plus defense-in-depth rather than the sole SIGABRT guard. Confirm.]
- [NEEDS CLARIFICATION: OQ-2 Shape of the depth-class error for upstream rejections. `NestingTooDeep { depth: usize }` requires a number upstream does not provide. Options: (a) new variant without a depth (for example an upstream-limit variant), (b) make `depth` optional on `NestingTooDeep`, (c) leave upstream rejections as `Syntax` and accept the ambiguity. Also verify `toml_span::ErrorKind` is public and matchable (and whether it is `#[non_exhaustive]`, which would force a wildcard arm) before choosing.]
- [NEEDS CLARIFICATION: OQ-3 Raise the workspace requirement from `toml-span = "0.7"` to `"0.7.2"`? Required if the pre-scan is removed (FR-009); optional but cheap if it is retained, since it prevents a resolver from silently selecting 0.7.1.]
- [NEEDS CLARIFICATION: OQ-4 Does toml-span 0.7.2 raise its own MSRV or add dependencies relative to the workspace `rust-version = "1.98"`? Not checked; the lock-bump issue should confirm.]
- [NEEDS CLARIFICATION: OQ-5 If the pre-scan is ever removed: worst-case stack usage of mixed-shape input at 128 levels (arrays of inline tables with dotted keys) on a 2 MiB stack, debug and release, is unmeasured. The 2026-10-06 evidence covers single-shape inputs in a debug build only.]
- [NEEDS CLARIFICATION: OQ-6 Should `MAX_TOML_NESTING_DEPTH` stay 64 or be aligned to upstream's 128? Research recommendation: stay 64 (real-world maximum is single digits; aligning removes the margin for the inline-table case). Confirm.]
- [NEEDS CLARIFICATION: OQ-7 Fuzzing: is the existing `parse_toml_checked` fuzz target plus seeds enough, or should a second target call `toml_span::parse` directly so the upstream guard is fuzzed independently of our pre-scan (which otherwise shields it from deep inputs)?]
- [NEEDS CLARIFICATION: OQ-8 Historical bisection figures (debug 220 inline tables / 305 arrays; release about 2485 / 1805 on 0.7.1): keep in the doc as a labeled historical note, or delete? Research recommendation: keep one sentence, labeled 0.7.1, since it documents why 64 was chosen.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-core/src/parser.rs` — `MAX_TOML_NESTING_DEPTH`, `check_toml_nesting_depth`, `parse_toml_checked`, `CheckedTomlError`
- `crates/deps-lsp/src/main.rs` — `WORKER_THREAD_STACK_SIZE`
- `fuzz/fuzz_targets/parse_toml_checked.rs` — shared TOML fuzz target
- Upstream: `EmbarkStudios/toml-span` PR #24, "Avoid stack overflow" (0.7.2 changelog)
- Related project history: #150, #1403, #1406 (shared checked-parse entry point and its fuzz target), #118 (incomplete-match bug class motivating exhaustive enums)

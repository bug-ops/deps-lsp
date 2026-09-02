---
aliases:
  - PyPI Package Completion Broken
  - pyproject.toml Completion Zero Results
tags:
  - sdd
  - spec
  - bug
  - completion
  - deps-pypi
  - pyproject-toml
created: 2026-08-24
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: PyPI Package-Name Completion Never Returns Results for Any Valid pyproject.toml Shape

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Branch**: (none yet)
> **Priority**: P1
> **Type**: bug
> **Discovered during**: ci-011 live-testing cycle, `.local/testing/lsp_test.py` completion mode against the debug binary at commit `20b6ff66` (v0.10.1, HEAD of `main`)

## 1. Overview

### Problem Statement

PyPI (`deps-pypi`) package-name completion (`textDocument/completion` while typing
a new dependency name in `pyproject.toml`) is completely non-functional for every
real-world `pyproject.toml` layout. This is a compound bug with two independent,
additive root causes in `crates/deps-lsp/src/handlers/completion.rs`.

**Root cause 1 — [[#FR-001|is_in_dependencies_section]] never recognizes PEP 621's actual `dependencies` array syntax.**

`is_in_toml_dependencies` (`crates/deps-lsp/src/handlers/completion.rs:381`, used for
both `EcosystemId::Cargo` and `EcosystemId::Pypi` via the match arm at line 333) walks
backward from the cursor line looking for a TOML section-header line that exactly
equals one of a fixed set of strings, including `"[project.dependencies]"`. But PEP
621 defines `project.dependencies` as an **array-of-strings key** under the
`[project]` table (`dependencies = [...]`), not as its own TOML subtable — writing
`[project.dependencies]` as a literal header is not how any real `pyproject.toml`
(including this very project's own `.local/testing/manifests/pyproject.toml` fixture,
and every tool-generated one: Poetry, Hatch, setuptools, uv, PDM) expresses it.
Because of this, the raw-text fallback completion path (`fallback_completion`,
`crates/deps-lsp/src/handlers/completion.rs:157`) can never trigger for the primary
`dependencies = [...]` array — the one virtually every `pyproject.toml` has — because
`is_in_dependencies_section` unconditionally returns `false` there.

`[project.optional-dependencies]` *is* a real, valid TOML subtable header (it's a
table of arrays, one array per named extra group), so it IS recognized — but see root
cause 2 for why even that path still returns 0 results.

**Root cause 2 — `extract_prefix` never strips the TOML quote character for PyPI, only for JSON-quoted-key ecosystems.**

`extract_prefix` (`crates/deps-lsp/src/handlers/completion.rs:225`) only trims a
leading/trailing `"` when `uses_json_quoted_keys(ecosystem_kind)` is `true` (npm's/
Composer's `"key": ...` JSON object-key shape). PyPI's `dependencies`/
`optional-dependencies` entries are TOML array *elements*
(`"requests>=2.31.0"`), a different quoting shape that `uses_json_quoted_keys` does
not cover and `uses_xml_tag_values` does not cover either. So even in the one section
where root cause 1 doesn't block the fallback path
(`[project.optional-dependencies]` groups), the extracted prefix keeps its literal
leading `"` character (e.g. typing `"pytes` yields prefix `"\"pyte"`, confirmed via
log line `fallback_completion: prefix = "\"pyte"`), which is then passed straight to
`search_packages`/the registry query. No real PyPI package name starts with a literal
`"`, so the search always returns 0 results (confirmed via log line
`search_packages: query="\"pyte", ecosystem=pypi` → `search_packages: found 0
results`) — the historical #148-class "quote-leak" defect (see
[[006-completion-prefix-quote-stripping/spec|Strip JSON string-delimiter quote from
fallback completion prefix]] for the npm/Composer sibling fix), but for TOML rather
than JSON, and specific to PyPI's array-of-strings dependency shape (Cargo's own
dependency completion types a bare/quoted TOML *key*, `foo = "1.0"`, a different code
shape that doesn't hit this same leak).

Net effect: **every** completion attempt anywhere in a `pyproject.toml` — in the
primary `dependencies` array (root cause 1 blocks it entirely) or in an
`optional-dependencies` group (root cause 2 empties the query) — returns zero
package-name suggestions.

Version completion for PyPI is NOT affected (independently live-verified working
correctly, 5 results with real PyPI data, in the same session) — this bug is specific
to package-*name* completion.

### Goal

Typing a partial package name anywhere inside a `pyproject.toml`
`dependencies = [...]` array (top-level `[project]` table) or an
`[project.optional-dependencies]` group's array must offer real, registry-backed
PyPI package-name completions — matching the working behavior already verified live
this session for Cargo, npm, Dart, Swift, Maven, Gradle, Composer, NuGet, and Deno
(all of which return real registry-backed completion items for an equivalent
partial-name scenario).

### Out of Scope

- Version completion for PyPI (already working, independently verified).
- Ecosystem-native (parsed, non-fallback) completion path
  (`ecosystem.generate_completions`) internals for PyPI, beyond confirming it also
  returns empty for these scenarios (already observed — the fix targets the fallback
  path, which is the one meant to cover "still typing" states).
- `requirements.txt` completion (separate manifest format, see
  [[009-pypi-requirements-txt/spec|Support requirements.txt (pip family) in deps-pypi]]
  if that ecosystem's completion needs the same shape of fix).
- Poetry's legacy `[tool.poetry.dependencies]` table shape (`requests = "^2.31.0"`,
  key-value not array-of-strings) — not confirmed live this cycle; flagged as an open
  question (Open Questions) since it may need a *third* code path rather than fitting
  cleanly into either fix below.
- Cargo's TOML dependency completion — already working correctly today, not touched
  by this fix; confirmed to use a different code shape (bare/quoted key, not array
  element) that does not share PyPI's quote-leak defect.

## 2. User Stories

### US-001: Package-name completion inside the primary `dependencies` array

AS A Python developer editing `pyproject.toml`
I WANT completion suggestions for real PyPI package names while typing inside the
top-level `dependencies = [...]` array
SO THAT I can add a new dependency without leaving the editor to look up the exact
package name.

**Acceptance criteria:**
```
GIVEN a pyproject.toml with
  [project]
  name = "myapp"
  version = "0.1.0"
  dependencies = [
      "requests>=2.31.0",
      "flas
  ]
WHEN textDocument/completion is requested with the cursor immediately after "flas"
THEN the response contains real PyPI package-name completion items whose names start
     with "flas" (e.g. "flask")
```

### US-002: Package-name completion inside an `optional-dependencies` group

AS A Python developer editing `pyproject.toml`
I WANT completion suggestions for real PyPI package names while typing inside an
`[project.optional-dependencies]` group's array (e.g. `dev = [...]`)
SO THAT optional/extra dependency groups get the same completion support as the
primary dependencies array.

**Acceptance criteria:**
```
GIVEN a pyproject.toml with
  [project.optional-dependencies]
  dev = [
      "pytes
  ]
WHEN textDocument/completion is requested with the cursor immediately after "pytes"
THEN the response contains real PyPI package-name completion items whose names start
     with "pytes" (e.g. "pytest"), not zero results, and the query sent to the
     registry does not contain a leading '"' character
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the cursor is on a line inside a `[project]` table's `dependencies = [...]` array (PEP 621 primary dependency list), THE SYSTEM SHALL recognize this as a dependencies section in `is_in_dependencies_section`/`is_in_toml_dependencies`, distinct from a literal `[project.dependencies]` header which does not occur in valid PEP 621 files | must |
| FR-002 | WHEN the cursor is on a line inside an `[project.optional-dependencies]` group's array, THE SYSTEM SHALL continue to recognize this as a dependencies section (already correct — regression guard only) | must |
| FR-003 | WHEN `extract_prefix` is called for `EcosystemId::Pypi` on a TOML array-element line (e.g. `"pytes`), THE SYSTEM SHALL strip the leading (and, if present, trailing) `"` from the extracted prefix, the same way it already strips leading/trailing `"` for JSON-quoted-key ecosystems | must |
| FR-004 | WHEN both FR-001/FR-002 and FR-003 hold, THE SYSTEM SHALL pass a quote-free prefix (e.g. `flas`, not `"flas` or `"\"fla"`) to `search_packages` for the PyPI registry | must |
| FR-005 | THE SYSTEM SHALL NOT regress existing dependency-section detection or prefix extraction for `EcosystemId::Cargo`, which shares `is_in_toml_dependencies` with PyPI but has no array-of-strings dependency shape and must remain on its current (working) code path | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | Unit tests for `is_in_toml_dependencies`/`is_in_dependencies_section` covering a `dependencies = [...]` array directly under `[project]` (no literal `[project.dependencies]` header present anywhere in the fixture) |
| NFR-002 | Correctness | Unit tests for `extract_prefix` with `EcosystemId::Pypi` on a still-typing TOML array-element line (`"flas`, unterminated) and a completed one (`"flask"`, cursor mid-token), asserting no leading/trailing `"` survives |
| NFR-003 | Regression safety | Existing `is_in_toml_dependencies`/`extract_prefix` tests for `EcosystemId::Cargo` continue to pass unmodified |
| NFR-004 | Live verification | Per project convention (`.claude/rules/continuous-improvement.md`), re-run `.local/testing/lsp_test.py` completion mode against the fixed debug binary for all three reproduction scenarios in this spec and confirm non-zero, real-registry results before closing |

## 5. Data Model

No new types. Affects `crates/deps-lsp/src/handlers/completion.rs` only:

| Function | Change |
|----------|--------|
| `is_in_toml_dependencies` (~line 381) | Recognize the `dependencies = [...]` array under `[project]` (and, per Open Questions, possibly `[tool.poetry.dependencies]`) in addition to the existing literal-header matches |
| `is_in_dependencies_section` (~line 327) | No signature change; may need PyPI split out of the shared `Cargo | Pypi` match arm if the array-detection logic diverges enough from Cargo's needs (see FR-005) |
| `extract_prefix` (~line 225) | Extend the quote-stripping condition to also cover PyPI's TOML array-element shape, without affecting Cargo |
| `uses_json_quoted_keys` (~line 305) | Likely NOT the right mechanism to extend, since it's documented as JSON-object-key-specific; a new PyPI-specific (or TOML-array-element-specific) predicate is more likely correct — implementation detail for `/sdd plan` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Cursor inside `dependencies = [...]` array, entry unterminated (user mid-typing, e.g. `"flas`) | Recognized as dependencies section (FR-001), prefix extracted quote-free (FR-003), real completions returned |
| Cursor inside `dependencies = [...]` array, entry already closed (e.g. `"flask"`, cursor between quotes) | Same as above — both the primary parsed path and the fallback path must agree this is a dependencies context |
| Cursor inside `[project.optional-dependencies]` group's array | Recognized (FR-002, already working), prefix extracted quote-free (FR-003) — currently broken only by root cause 2 |
| Cursor inside `[tool.poetry.dependencies]` (legacy Poetry table syntax, key-value not array) | Not confirmed live this cycle — see Open Questions; must not be silently broken by the FR-001 fix, but may remain a known gap if out of scope |
| Cursor on a line inside `dependencies = [...]` that is NOT a string literal (e.g. blank line inside the array, or the closing `]`) | Existing prefix-rejection logic (`prefix.is_empty() || ... < 2 chars`) already filters this out — no new handling needed |
| Cursor inside a `[build-system] requires = [...]` array (also array-of-strings, but not a "dependency" the user manages day-to-day the same way) | Out of scope per Goal (user-managed dependencies only) — confirm in `/sdd plan` whether build-system requirements should also get completion, but not required for this fix |
| Cargo.toml with a `[dependencies]` table (Cargo's actual, correct syntax) | Unaffected — FR-005 regression guard |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live completion request for reproduction scenario 1 (unterminated `"flas` inside top-level `dependencies` array) | Non-zero PyPI package-name completion items returned, matching prefix `flas` |
| SC-002 | Live completion request for reproduction scenario 2 (closed `"flas"` entry, same array) | Non-zero PyPI package-name completion items returned |
| SC-003 | Live completion request for reproduction scenario 3 (`"pytes` inside `[project.optional-dependencies]` `dev` group) | Non-zero PyPI package-name completion items returned; debug log shows `search_packages: query="pytes"` with no leading `"` |
| SC-004 | `cargo nextest run -p deps-lsp` | All pass, including new fixture-based tests from NFR-001/NFR-002 |
| SC-005 | Cargo.toml completion regression check (`.local/testing/manifests/Cargo.toml` or equivalent fixture) | Unchanged behavior — still returns correct completions, confirming FR-005 |

## 8. Agent Boundaries

### Always (without asking)
- Fix `is_in_toml_dependencies`/`is_in_dependencies_section` to recognize PEP 621's
  `dependencies = [...]` array shape for PyPI
- Fix `extract_prefix` to strip the leading/trailing `"` for PyPI's TOML
  array-element shape
- Add unit tests per NFR-001/NFR-002
- Run `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run -p deps-lsp --all-features`
- Live-verify all three reproduction scenarios per NFR-004 before marking the fix
  complete, using `.local/testing/lsp_test.py` completion mode against a freshly
  built debug binary
- Confirm Cargo completion is unaffected by re-running its existing passing tests
  and a live spot-check (FR-005/SC-005)

### Ask First
- Whether to also handle `[tool.poetry.dependencies]` (legacy Poetry key-value
  syntax) in the same fix or file it as a separate follow-up issue (see Open
  Questions) — it is a materially different TOML shape (table of key-value pairs,
  not an array) and may need its own detection branch
- Whether `[build-system] requires = [...]` should get the same completion treatment
  — out of scope per Goal, but the array-detection logic this fix adds may make it a
  near-zero-cost addition worth a quick decision

### Never
- Modify Cargo's dependency-section detection or prefix extraction in a way that
  changes its current (correct) behavior
- Introduce a second registry round trip or otherwise change completion latency
  characteristics — this is a pure text-detection/string-extraction fix
- Touch PyPI's version-completion path — confirmed already working, out of scope

## 9. Open Questions

> [!question] Poetry legacy syntax
> [NEEDS CLARIFICATION: Should `[tool.poetry.dependencies]` (Poetry's pre-PEP-621
> key-value table syntax, e.g. `requests = "^2.31.0"`) get the same completion fix in
> this same PR, or is it a separate follow-up? It wasn't part of the live-reproduced
> evidence this cycle (only PEP 621 `[project.dependencies]`/
> `[project.optional-dependencies]` were tested), and it's a structurally different
> TOML shape (table, not array) that may need a distinct detection branch rather than
> reusing FR-001's array-detection logic. Recommend scoping it in during `/sdd plan`
> if low-cost, otherwise filing a separate P2/P3 follow-up issue.]

> [!question] `[project.dependencies]` literal-header dead code
> [NEEDS CLARIFICATION: Once FR-001 adds real `dependencies = [...]` array detection,
> should the now-confirmed-dead `line == "[project.dependencies]"` literal-header
> match in `is_in_toml_dependencies` be removed as cleanup, or left in place as
> harmless defensive code in case some non-standard tool ever emits it? Recommend
> removing it during `/sdd plan`/implementation to avoid misleading future readers
> into thinking it's the reason PEP 621 completion works.]

## 10. See Also

- [[MOC-specs]] — all specifications
- [[006-completion-prefix-quote-stripping/spec|Strip JSON string-delimiter quote from fallback completion prefix]] — the npm/Composer sibling of root cause 2, same class of defect (#148-class quote-leak) in a different quoting shape
- [[009-pypi-requirements-txt/spec|Support requirements.txt (pip family) in deps-pypi]] — related PyPI manifest-format work, separate file format from pyproject.toml
- `crates/deps-lsp/src/handlers/completion.rs` — `is_in_dependencies_section` (~line 327), `is_in_toml_dependencies` (~line 381), `fallback_completion` (~line 157), `extract_prefix` (~line 225), `uses_json_quoted_keys` (~line 305)
- `.local/testing/manifests/pyproject.toml` — existing project fixture that itself demonstrates the bug (uses `dependencies = [...]`, never `[project.dependencies]`)
- `.local/testing/journal/ci-011.md` — live-testing cycle that discovered this finding (2026-08-24)

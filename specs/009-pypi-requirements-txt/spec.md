---
aliases:
  - requirements.txt Support in deps-pypi
  - Plain Requirements Files
tags:
  - sdd
  - spec
  - enhancement
  - parity-gap
  - ecosystem/pypi
  - priority/p2
created: 2026-08-23
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: Support requirements.txt (pip family) in deps-pypi

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-08-23 (research finding)
> **Branch**: [NEEDS CLARIFICATION: assign issue number before branching, e.g. `feat/<issue>-requirements-txt`]
> **Type**: enhancement / competitive-parity gap — this spec documents WHAT is missing and WHY;
> the HOW (file detection routing, parser adaptation, requires.txt precedent patterns) is deferred to a future `/sdd plan` session.

## 1. Overview

### Problem Statement

deps-pypi currently targets `pyproject.toml` only (PEP 621, PEP 735, Poetry). Plain `requirements*.txt`
— still the most common Python dependency file across standalone scripts, data-science notebooks,
Docker container specs, and legacy projects — has zero handling in the repo, despite being explicitly
listed in `.claude/rules/continuous-improvement.md`'s cross-ecosystem manifest inventory.

Verified this cycle (2026-08-23) via:
```
rg "requirements\.txt" crates/deps-pypi/src/ --type rust
# => no output (zero hits)
```

Every direct competitor and both update bots cover requirements.txt: Dependi, Renovate (`pip_requirements`
manager), Dependabot (`pip_requirements` config), and a dedicated VS Code extension (pypi-assistant)
existing solely to serve this format. The gap is not a minor edge case — requirements.txt is the
de-facto standard for distributing Python dependencies in many contexts outside of modern
PEP 621 / Poetry workflows.

This finding was identified in the competitive-parity research playbook
(`.local/testing/playbooks/competitive-parity.md`, Scan Notes 2026-08-23) as the **top
audience-per-effort finding** of the scan: the registry client (PEP 691 Simple JSON API) and version
comparison logic (`pep440_rs`) are reused unchanged — this is **parser + file-detection work only**.

### Goal

deps-pypi recognizes and parses `requirements.txt`, `requirements-*.txt`, and `*.requirements.txt`
files, extracting dependencies in the same way `pyproject.toml` is parsed, routing them through the
existing LSP handlers (`hover`, `completion`, `inlay_hint`, `diagnostic`, `code_action`) so that
plain requirements files receive identical version-checking feedback as modern PEP 621 manifests.

### Out of Scope

- Recursive include resolution (`-r` / `--requirement` directives) — parsing SHALL tolerate these
  lines without error, but whether to resolve/follow them is an open design question for `/sdd plan`.
- Constraints files (`constraints.txt`) — distinct file type with its own semantics; out of scope.
- Line-based options (`--index-url`, `--extra-index-url`, `--hash`, `--global-options`, etc.) — these
  are pip configuration directives, not dependency specifiers. The parser SHALL skip them gracefully.
- Editable installs (`-e`) — the parser SHALL recognize and skip these lines gracefully (print a debug
  warning if verbosity is enabled, but do not surface an error or diagnostic to the user).
- Direct URLs and local paths (`file://`, `git+https://`, `/path/to/local`) — the parser SHALL skip
  these gracefully, as they are not resolvable via the PyPI registry.
- Private/alternative registries (`-i`, `--index-url`, `--extra-index-url` configuration) — those are
  separate, unfiled candidates that require auth/config design; out of scope here. An open question
  below flags this for later.
- Nested include cycles (detecting circular `-r` includes) — an open question.
- Lockfile support for requirements.txt (e.g., `requirements.lock` or vendor-specific lockfile formats
  beyond Poetry's `poetry.lock` and uv's `uv.lock`) — out of scope; lockfile support is a separate
  orthogonal concern per-ecosystem.

## 2. User Stories

### US-001: Plain requirements.txt receives the same version feedback as pyproject.toml

AS A Python developer using a plain `requirements.txt` file (not a modern `pyproject.toml`)
I WANT to see the same hover information, latest-version inlay hints, outdated diagnostics,
version completion, and update code actions in my requirements.txt as I would get in a
pyproject.toml
SO THAT I can keep my dependencies up to date without duplicating tools or switching between
editors/extensions.

**Acceptance criteria:**
```
GIVEN an open requirements.txt containing N dependencies (e.g., "requests>=2.28.0")
WHEN I hover over a dependency name or version specifier
THEN the server returns hover content identical in format and structure to what would be
     returned for the same dependency in a pyproject.toml (package name, current version,
     latest version, status label)

GIVEN an open requirements.txt with one or more outdated dependencies
WHEN the editor requests inlay hints for that document
THEN the server returns inlay-hint entries at the version specifier, showing the latest
     resolvable version, identical to the behavior for pyproject.toml

GIVEN an open requirements.txt with one or more unknown/yanked/outdated dependencies
WHEN the editor requests diagnostics for that document
THEN the server returns diagnostic entries with the same messages, severity levels, and
     locations as for pyproject.toml dependencies in the same state
```

### US-002: Graceful handling of requirements.txt-specific syntax

AS A Python developer with a diverse requirements.txt containing comments, environment
markers, editable installs, and include directives
I WANT the LSP server to extract resolvable dependencies without crashing or surfacing
errors for non-resolvable lines
SO THAT the LSP service degrades gracefully and still provides useful feedback on the
dependencies I *can* manage.

**Acceptance criteria:**
```
GIVEN a requirements.txt with:
  - Inline comments (e.g., "requests>=2.28  # for HTTP support")
  - Blank lines and comment-only lines
  - PEP 508 environment markers (e.g., "dataclasses>=0.6 ; python_version < '3.7'")
  - Editable installs (e.g., "-e ./local-package" or "-e git+https://...")
  - Direct URLs (e.g., "flask @ https://...")
  - Include directives (e.g., "-r base-requirements.txt")
  - Line-based options (e.g., "--index-url https://...", "--hash sha256:...")
WHEN the parser processes this file
THEN it SHALL:
  - Extract dependencies from resolvable lines
  - Skip non-resolvable lines (editable, URL, option lines) without error
  - Preserve and apply PEP 508 environment markers to dependencies
  - Print debug-level logging for skipped lines (if verbosity enabled)
  - Return a parse result with only the resolvable dependencies, no partial-parse errors
```

### US-003: Consistent behavior across ecosystem requirements formats

AS A developer using deps-lsp with multiple ecosystems (e.g., Python, Node.js, Ruby)
I WANT the requirements.txt feature to follow the same LSP feature-consistency rules as
other ecosystem crates (per `.claude/rules/continuous-improvement.md#Cross-Ecosystem
Consistency Testing`)
SO THAT I don't encounter surprise divergences in hover/completion/diagnostic formatting
between manifest types.

**Acceptance criteria:**
```
GIVEN two dependency-manifest files with equivalent outdated-status dependencies:
  - File 1: "requests>=2.28" in a requirements.txt (outdated, assuming latest is 2.31)
  - File 2: "requests = '2.28'" in a pyproject.toml (outdated)
WHEN LSP handlers (hover, inlay hints, diagnostics) are invoked on both
THEN the hover title, status label (e.g., "outdated"), latest-version display, and
     update code action SHALL be identical in format and wording, demonstrating
     cross-ecosystem consistency per the documented rule
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL extend `PypiEcosystem::manifest_filenames()` in `crates/deps-pypi/src/ecosystem.rs` (currently returning `["pyproject.toml"]`) to include patterns matching `requirements.txt`, `requirements-*.txt` (e.g., `requirements-dev.txt`), and `*.requirements.txt` (e.g., `app.requirements.txt`) | must |
| FR-002 | THE SYSTEM SHALL extend the PyPI parser in `crates/deps-pypi/src/parser.rs` to accept plain-text requirements.txt content (newline-separated dependency specifiers) in addition to TOML, detecting file format from either file extension or content heuristics | must |
| FR-003 | WHEN parsing a requirements.txt THE SYSTEM SHALL extract each non-comment, non-option, non-editable, non-URL line as a potential dependency specifier and attempt to parse it as a PEP 508 requirement, reusing the existing `parse_pep508_requirement()` logic already in use for pyproject.toml | must |
| FR-004 | THE SYSTEM SHALL preserve and apply PEP 508 environment markers (e.g., `; python_version < '3.8'`) found on each dependency line in requirements.txt, reusing the existing marker-handling logic (see `crates/deps-pypi/src/parser.rs` line ~4, `pep508_rs::MarkerTree`) consistent with pyproject.toml marker handling from issue #140 | must |
| FR-005 | THE SYSTEM SHALL gracefully skip (without surfacing an error or diagnostic to the user) lines that are: comments (lines beginning with `#`), blank lines, editable installs (`-e ...`), direct URLs (lines containing `@`, `://`, or `file://`), line-based options (`--index-url`, `--hash`, etc.), and include directives (`-r`, `--requirement`, `-c`, `--constraint`), printing debug-level logging (if tracing is enabled) for each skipped line | must |
| FR-006 | THE SYSTEM SHALL route parsed requirements.txt dependencies through the existing LSP handlers — `generate_hover()`, `generate_inlay_hints()`, `generate_diagnostics()`, `generate_completions()`, `generate_code_actions()` in `crates/deps-pypi/src/ecosystem.rs` — so that hover, completion, inlay hint, diagnostic, and code action behavior are identical to pyproject.toml dependencies, per the cross-ecosystem-consistency rule | must |
| FR-007 | WHEN a `requirements.txt` file is edited (e.g., version specifier changed) THE SYSTEM SHALL re-parse the file on the next `textDocument/didChange` or handler invocation rather than serving stale parsed state | must |
| FR-008 | THE SYSTEM SHALL handle case-insensitive dependency names (per PEP 503 normalization) in requirements.txt identically to how they are handled in pyproject.toml, ensuring that "Requests", "requests", and "REQUESTS" all resolve to the same PyPI package | should |
| FR-009 | THE SYSTEM SHALL [NEEDS CLARIFICATION: determine design intent for `-r`/`--requirement` and `-c`/`--constraint` directives: (A) skip them silently (current proposal, simplest), (B) follow them and merge transitive dependencies into the parse result, or (C) surface a diagnostic suggesting the user resolve includes manually]. This decision is deferred to `/sdd plan` but SHALL be made before implementation. | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Parsing a requirements.txt file SHALL NOT perform additional registry HTTP calls beyond what diagnostics/inlay hints already perform for the same dependencies in pyproject.toml — reuse existing cached version data from `deps_core::HttpCache` |
| NFR-002 | Performance | Parse latency for a requirements.txt with N dependencies SHALL be in the same order of magnitude as parsing a pyproject.toml with the same N dependencies, since both reuse the same dependency-extraction and PEP 508 parsing logic |
| NFR-003 | Correctness | PEP 440 version specifier parsing and PEP 508 requirement parsing SHALL be identical between requirements.txt and pyproject.toml — both MUST use the same parsing functions (currently `pep508_rs` crate) |
| NFR-004 | Consistency | Environment-marker behavior (e.g., markers that evaluate to `false` on the current platform) SHALL be identical between requirements.txt and pyproject.toml — both MUST respect the same marker semantics |
| NFR-005 | Consistency | Hover/diagnostic/inlay-hint formatting (title, status labels, code blocks) SHALL be identical across requirements.txt and pyproject.toml dependencies, per cross-ecosystem-consistency rule in `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` — any divergence is a first-class bug |
| NFR-006 | Compatibility | Adding requirements.txt support SHALL NOT alter existing pyproject.toml parsing, LSP behavior, or feature behavior — this is an additive capability |
| NFR-007 | Robustness | The parser SHALL NOT crash, panic, or hang on malformed, circular, or deeply nested requirements.txt content (e.g., very long lines, malformed PEP 508 specifiers, deeply nested markers per `.claude/rules/continuous-improvement.md`) — errors SHALL be caught and logged, with partial parse results returned |
| NFR-008 | User Experience | Diagnostics and messages produced by LSP handlers for requirements.txt dependencies SHALL use terminology consistent with pyproject.toml (no file-format-specific jargon), so a user sees "package is outdated" rather than "requirement is outdated" or ecosystem-specific wording |

## 5. Data Model

No new persistent entities. Requirements.txt parsing reuses the existing `PypiDependency` struct
(defined in `crates/deps-pypi/src/types.rs`) and parse result types already used for pyproject.toml.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Requirements.txt content (plain text) | Newline-separated dependency specifiers, comments, markers, and pip directives | file URI, content string (parsed into `Vec<PypiDependency>` by the parser) |
| Parsed requirements.txt dependencies (reused from pyproject.toml) | Extracted dependencies with their names, version specifiers, extras, environment markers, source location (line/column range in the requirements.txt) | `PypiDependency`: name, version_spec, extras, markers, section, line range |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Empty requirements.txt | Parser returns parse result with empty dependency vector; no LSP feedback needed |
| requirements.txt with only comments and blank lines | Parser returns empty dependency vector; no LSP feedback |
| Dependency with inline comment (e.g., `requests>=2.28  # HTTP library`) | Parser extracts "requests>=2.28" (comment stripped), processes normally |
| Dependency with PEP 508 marker (e.g., `dataclasses>=0.6 ; python_version < '3.7'`) | Parser extracts marker, passes to existing marker-handling logic (reuse from pyproject.toml #140); marker evaluates at runtime to determine if dependency is applicable |
| Editable install line (e.g., `-e ./local-package`) | Parser skips this line gracefully, prints debug log, does NOT surface error to user |
| Direct URL dependency (e.g., `flask @ https://github.com/pallets/flask/archive/refs/heads/main.zip`) | Parser skips this line, prints debug log (not resolvable via PyPI registry) |
| Include directive (e.g., `-r base-requirements.txt`) | [NEEDS CLARIFICATION: see FR-009 — design intent not yet determined; pending `/sdd plan`] |
| Line-based options (e.g., `--index-url https://pypi.example.com/simple`, `--hash sha256:...`) | Parser skips this line, prints debug log (these are pip configuration, not dependency specifiers) |
| Malformed PEP 508 specifier (e.g., `requests~@2.28` with invalid operator) | Parser logs a warning, skips the line (graceful degradation); returns partial parse result with other valid dependencies |
| Very large requirements.txt (hundreds of lines, many invalid) | Parser processes all lines, accumulates valid dependencies, skips invalid lines with debug logging; returns complete parse result in reasonable time (no new registry calls beyond what would be made for equivalent pyproject.toml) |
| Circular `-r` include (e.g., `base.txt` includes `dev.txt` which includes `base.txt`) | [NEEDS CLARIFICATION: design intent not yet determined; see FR-009] |
| requirements.txt with mixed case package names (e.g., "Requests", "requests") | Parser normalizes names per PEP 503 (lowercase + underscore-to-hyphen normalization) and matches them to the same PyPI package |
| Parser encounters a dependency already in pyproject.toml | No special handling — both files are parsed independently; if a user has both files in the same project, they see duplicate diagnostics/hovers for the same package (consistent with how VS Code displays the same file open in two tabs) — [NEEDS CLARIFICATION: is deduplication a future feature or user's responsibility?] |
| requirements.txt is edited while an LSP handler is running | Parsing is triggered on `textDocument/didChange`; subsequent handler invocations use the updated parse result; no concurrent-access issues (LSP client synchronizes) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `manifest_filenames()` includes requirements patterns | `PypiEcosystem::manifest_filenames()` returns at least `["pyproject.toml", "requirements.txt"]` (exact glob set confirmed in `/sdd plan`) |
| SC-002 | Hover for requirements.txt dependencies matches pyproject.toml | A package in requirements.txt and pyproject.toml with identical version specifier produces identical hover content (format, status label, latest version) — verified manually in a test manifest |
| SC-003 | Inlay hints for requirements.txt match pyproject.toml | Inlay-hint positions, text, and appearance are identical between requirements.txt and pyproject.toml for the same package state (outdated/unknown/yanked) |
| SC-004 | Diagnostics for requirements.txt match pyproject.toml | Diagnostic messages, severity levels, and line-range locations are identical for equivalent dependencies in both file formats |
| SC-005 | Parser handles PEP 508 markers | An environment marker like `; python_version < '3.8'` is parsed and applied consistently with pyproject.toml marker handling (reusing existing logic from issue #140) |
| SC-006 | Parser gracefully skips non-resolvable lines | A requirements.txt with `-e`, `--index-url`, direct URLs, comments, and editable installs is parsed without errors; parse result contains only resolvable dependencies |
| SC-007 | No duplicate registry calls | Parsing requirements.txt introduces zero additional HTTP calls to PyPI registry beyond what diagnostics/inlay hints already perform for the same dependencies in pyproject.toml, verified via debug logs |
| SC-008 | Cross-ecosystem consistency test passes | A live-testing session (per `.local/testing/` protocol) opens a requirements.txt and a pyproject.toml with identical dependencies and verifies hover/completion/diagnostic/inlay-hint behavior is equivalent; results logged in `.local/testing/coverage.md`'s LSP Feature Matrix |

## 8. Agent Boundaries

### Always (without asking)
- Reuse the existing `PypiDependency` struct, PEP 508 parsing, and PEP 440 version-comparison logic;
  do not duplicate them for requirements.txt.
- Extend `manifest_filenames()` in `PypiEcosystem` to include the new file patterns; do not hard-code
  file-type detection in the LSP server.
- Route requirements.txt dependencies through the existing LSP handler functions (`generate_hover()`,
  `generate_inlay_hints()`, etc.); ensure behavior is identical to pyproject.toml per
  cross-ecosystem-consistency rule.
- Follow existing patterns in `crates/deps-pypi/src/parser.rs` for error handling, marker parsing,
  and logging.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features
  --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering
  any implementation complete.

### Ask First
- Introducing a new error type distinct from existing `PypiError` variants (vs. reusing `PypiError::ParseError`).
- Changing the `PypiDependency` struct to add new fields (vs. reusing existing fields).
- Making the requirements.txt parser respect `-r`/`-c` includes (vs. skipping them silently) — this
  is a design decision for `/sdd plan`.
- Adding a new public API to `PypiEcosystem` beyond extending `manifest_filenames()` and updating
  `parse_manifest()` to handle both file types.

### Never
- Modify existing pyproject.toml parsing logic as a side effect of adding requirements.txt support
  — the two formats MUST be parsed independently.
- Surface a diagnostic or error to the user for requirements.txt-specific syntax that cannot be
  resolved (editable installs, direct URLs, include directives) — graceful skipping is required.
- Diverge from the cross-ecosystem-consistency rule — hover/diagnostic/inlay-hint format MUST
  remain identical between requirements.txt and pyproject.toml.
- Introduce ecosystem-specific LSP behavior for requirements.txt that differs from how pyproject.toml
  dependencies are handled.

## 9. Open Questions

- [NEEDS CLARIFICATION: Exact file-pattern matching — should the system recognize `requirements.txt`,
  `requirements-*.txt`, and `*.requirements.txt`? Or only `requirements*.txt`? The competitive-parity
  note mentions all three; the final set of globs is a `/sdd plan` decision.]
- [NEEDS CLARIFICATION: Design intent for `-r`/`--requirement` and `-c`/`--constraint` include
  directives (FR-009): (A) skip them silently (simplest, proposed), (B) follow them recursively
  and merge transitive dependencies, or (C) surface a warning diagnostic? This decision must be
  made in `/sdd plan` before implementation. Recursive include detection (cycle prevention) is a
  sub-question if (B) is chosen.]
- [NEEDS CLARIFICATION: Should constraints.txt (e.g., `constraints.txt`, typically used with `-c`
  directives) be treated as a distinct file type with different semantics, or grouped with
  requirements.txt? Currently scoped out; deferred decision.]
- [NEEDS CLARIFICATION: Handling of `--hash` lines — should these be parsed for integrity-check
  purposes, or simply skipped as pip configuration? If parsed, should a mismatch between installed
  and declared hashes surface a diagnostic?]
- [NEEDS CLARIFICATION: If a user has both `requirements.txt` and `pyproject.toml` in the same
  project with overlapping dependencies, should the server deduplicate diagnostics, or should the
  user see redundant feedback for the same package? Currently proposed: independent parsing, user
  sees both (consistent with text-editor tab duplication UX). Deferred to `/sdd plan` if
  deduplication is desired.]
- [NEEDS CLARIFICATION: Should the parser attempt to infer the Python version / environment markers
  from project metadata (e.g., `python_requires` in pyproject.toml), or evaluate markers in a
  platform-neutral way? Currently proposed: reuse existing marker-evaluation logic from pyproject.toml
  handling (issue #140), which may also have this open question. Verify during plan.]
- [NEEDS CLARIFICATION: No project constitution exists yet at `.local/specs/constitution.md` — this
  spec cannot yet be checked against project-wide architectural principles. Recommend running
  `/sdd init` before `/sdd plan` for this feature.]

## 10. See Also

- `crates/deps-pypi/src/ecosystem.rs` — `manifest_filenames()` method (~line 70-72), `parse_manifest()`
  method (~line 78-92)
- `crates/deps-pypi/src/parser.rs` — `PypiParser::parse_content()` (~line 145-212), PEP 508 marker
  handling (~line 4-60, `marker_too_deep()`, `MAX_MARKER_LEN`, `MAX_MARKER_DEPTH`), existing
  `parse_pep508_requirement()` logic for reuse
- `crates/deps-pypi/src/types.rs` — `PypiDependency` struct definition (to be reused)
- `.local/testing/issue-drafts-2026-08-23.md` — Draft 1 (original issue body)
- `.local/testing/playbooks/competitive-parity.md` — Known Gaps table row, Scan Notes (2026-08-23)
- `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` — consistency rule
  this feature MUST comply with
- [[MOC-specs]] — all specifications
- [PEP 440 — Version Identification and Dependency Specification](https://peps.python.org/pep-0440/)
- [PEP 508 — Dependency specification for Python Software Packages](https://peps.python.org/pep-0508/)
- [PEP 691 — JSON API for the Simple Repository API](https://peps.python.org/pep-0691/)
- [pip requirements file format documentation](https://pip.pypa.io/en/stable/reference/requirements-file-format/)

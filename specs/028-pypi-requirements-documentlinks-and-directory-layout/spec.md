---
aliases:
  - PyPI requirements.txt documentLinks
  - requirements/*.txt directory layout
tags:
  - sdd
  - spec
  - enhancement
  - deps-pypi
  - lsp-protocol
  - security
created: 2026-09-02
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[009-pypi-requirements-txt/spec|Support requirements.txt (pip family) in deps-pypi]]"
  - "[[027-nuget-unlisted-version-and-multiproject-lockfile/spec|NuGet unlisted-version hover marker and multi-project lock file matching]]"
---

# Feature: PyPI `requirements.txt` `-r`/`-c` documentLinks and `requirements/*.txt` Directory-Layout Recognition

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Status**: Shipped — PR #458 (issue #452)
> **Priority**: P3
> **Type**: enhancement / security-hardening

## 1. Overview

### Problem Statement

Two `TODO(critic)` markers in the `requirements.txt`-family handling
(`deps-pypi`) documented known gaps with no linked issue, per issue #452:

1. **`-r`/`-c` targets not surfaced as documentLinks**
   (`crates/deps-pypi/src/parser/requirements.rs:20`, pre-fix): a
   `-r other-requirements.txt` / `-c constraints.txt` reference inside a
   `requirements.txt` was parsed (to skip it as a non-dependency option
   line) but never exposed as an LSP `documentLink`, so a user could not
   ctrl/cmd-click the reference to jump to the referenced file.
2. **`requirements/*.txt` layout unsupported**
   (`crates/deps-core/src/ecosystem_registry.rs:284`,
   `EcosystemRegistry::get_for_uri`, pre-fix): ecosystem lookup was
   filename-basename-only, so the common convention of splitting
   `requirements.txt` into `requirements/base.txt`,
   `requirements/dev.txt`, etc. was never recognized — a bare basename
   match cannot see the directory a file lives in, only the file itself.

Both markers were explicit, accepted-but-unfiled TODOs; PR #458 closed
both as issue #452, alongside a comparable pair of `deps-nuget` gaps
(issue #451, tracked separately — see [[027-nuget-unlisted-version-and-multiproject-lockfile/spec|the sibling spec]]).

### Goal (achieved)

- `-r`, `-c`, `--requirement`, and `--constraint` option targets in
  `requirements.txt` are surfaced as `textDocument/documentLink` entries,
  resolvable to the referenced file, with the click target validated
  against link-spoofing before being shown.
- A `requirements/*.txt` directory layout is recognized by
  `EcosystemRegistry::get_for_uri` as a PyPI manifest, routed through a
  stricter parse gate than a primary basename match, so a same-named but
  unrelated `.txt` file (e.g. a prose requirements-engineering document
  under a folder literally named `requirements/`) is not misclassified
  as a Python manifest and does not trigger spurious PyPI network
  lookups.

### Out of Scope

- Any change to dependency parsing/version resolution for
  `requirements.txt` itself — this PR only adds documentLinks and
  broadens which files are *routed* to the existing parser, not how
  dependencies inside them are parsed.
- `pyproject.toml`'s own file references (unaffected; this spec is
  `requirements.txt`-family only).
- General Unicode security hardening beyond the specific bidi/format/
  zero-width character classes enumerated in FR-003 (not a general
  Unicode-normalization pass).

## 2. User Stories

### US-001: Navigate to a referenced requirements/constraints file

AS A developer with a split `requirements.txt` (`-r base.txt` /
`-c constraints.txt` references)
I WANT to ctrl/cmd-click the referenced filename to jump straight to it
SO THAT I don't have to manually locate the file in the project tree

**Acceptance criteria:**
```
GIVEN a requirements.txt containing "-r other-requirements.txt"
WHEN the client requests textDocument/documentLink
THEN a DocumentLink is returned whose range covers exactly the target
  text ("other-requirements.txt") and whose target URI resolves to that
  file relative to the containing document's directory, with a tooltip
  showing the resolved absolute path
```

### US-002: Link target cannot be spoofed via bidi/zero-width characters

AS A developer opening an untrusted or unreviewed repository
I WANT a documentLink's visible text and its actual click target to
never diverge because of hidden Unicode formatting characters
SO THAT a hostile `requirements.txt` cannot make a link that reads as
one file but opens another

**Acceptance criteria:**
```
GIVEN a -r/-c target string containing a bidi override, zero-width
  joiner, or other control/format character from the rejected set
WHEN document links are generated
THEN no DocumentLink is produced for that line, and the rejection is
  logged via the shared warn_rejected_value helper — the file is
  otherwise unaffected (its dependencies still parse normally)
```

### US-003: `requirements/*.txt` split-file layout is recognized without misclassifying prose

AS A developer using the `requirements/base.txt` / `requirements/dev.txt`
split-file convention
I WANT those files recognized as PyPI manifests with live hover/
diagnostics
SO THAT I get the same LSP value a root-level `requirements.txt` gets

**Acceptance criteria:**
```
GIVEN a file at requirements/base.txt with real pip-style content
WHEN the LSP routes the file via EcosystemRegistry::get_for_uri
THEN it resolves to the PyPI ecosystem and parses/reports normally

GIVEN a file at requirements/introduction.txt that is prose (e.g. a
  requirements-engineering document, not a Python manifest) whose lines
  happen to parse as bare unpinned package names
WHEN the LSP routes the file via the directory-pattern fallback
THEN the stricter (require_strong_signal) parse gate drops the false
  positive — no dependencies are reported and no PyPI network request is
  made
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a `requirements.txt`-family file contains a `-r`, `-c`, `--requirement`, or `--constraint` option line (space-separated or `--long=value` form) with a non-empty target THE SYSTEM SHALL record a document-link reference spanning exactly the target text's byte range, for both option spellings | must |
| FR-002 | WHEN `Ecosystem::generate_document_links` is called with a parse result containing such references THE SYSTEM SHALL resolve each target relative to the containing document's directory (skipping targets already containing a URL scheme, e.g. `http://`) and return one `DocumentLink` per reference with a tooltip showing the resolved absolute path | must |
| FR-003 | WHEN a link target contains an ASCII control character, a bidi override/embedding/isolate character (U+200E-U+200F, U+202A-U+202E, U+2066-U+2069), a zero-width joiner/space/no-break character (U+200B-U+200D, U+2060, U+FEFF), or a JS/JSON5 line terminator (U+2028, U+2029) THE SYSTEM SHALL reject the target (no `DocumentLink` produced) and log via `warn_rejected_value`, closing a link-target/tooltip spoofing vector | must — security |
| FR-004 | THE SYSTEM SHALL add `Ecosystem::manifest_directory_patterns() -> &[(&'static str, &'static str)]` (default empty), and `EcosystemRegistry::get_for_uri` SHALL consult it — matching a file directly inside a named directory whose basename ends with the declared suffix — only after both `manifest_filenames` and `manifest_patterns` (basename-only) checks miss | must |
| FR-005 | PyPI's `manifest_directory_patterns()` SHALL declare `[("requirements", ".txt")]`, recognizing any `*.txt` file directly inside a directory literally named `requirements/` | must |
| FR-006 | WHEN a `requirements.txt`-family file was routed to the PyPI parser via the directory-pattern fallback (i.e., its basename matched neither `manifest_filenames` nor `manifest_patterns`) THE SYSTEM SHALL parse it with `require_strong_signal: true`, dropping the ratio-based ("more lines parsed than failed") keep-arm and requiring a genuine pip-option or version/Git/URL-bearing line to keep any dependencies — preventing prose files that happen to contain bare-word lines from being misclassified as a manifest | must |
| FR-007 | WHEN a file's basename directly matches `manifest_filenames`/`manifest_patterns` (the pre-existing primary routes) THE SYSTEM SHALL continue to parse with `require_strong_signal: false`, unchanged from pre-fix behavior (no regression for root-level `requirements.txt`/`constraints.txt`) | must |
| FR-008 | `EcosystemRegistry::get_for_lockfile` SHALL support the same single-`*`-wildcard prefix/suffix pattern scheme in `lockfile_filenames()` entries that `manifest_patterns` already used, reusing one shared `prefix_suffix_matches` helper (DRY with the directory-pattern and lockfile matchers; the NuGet half of PR #458 is the pattern's first consumer, see [[027-nuget-unlisted-version-and-multiproject-lockfile/spec|027]]) | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | Zero regression for root-level `requirements.txt`/`constraints.txt`: existing basename-routed files keep the pre-fix lenient (`require_strong_signal: false`) gate, verified by the existing `deps-pypi` test suite passing unmodified |
| NFR-002 | Security | Link-target validation (FR-003) runs before any `DocumentLink` is constructed — no partially-validated or best-effort tooltip is ever shown for a rejected target |
| NFR-003 | Maintainability | Directory-pattern matching (`get_for_directory_pattern`) and lockfile wildcard matching (`lockfile_pattern_matches`) both reuse the single `prefix_suffix_matches` helper rather than duplicating the length/`starts_with`/`ends_with` check a third time |
| NFR-004 | Performance | `get_for_directory_pattern` is only consulted when both faster basename checks (`manifest_filenames` exact lookup, `manifest_patterns` glob scan) already missed — no added cost for the common case of a root-level manifest |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `RequirementRef` (new, `deps-pypi::parser`) | One parsed `-r`/`-c`/`--requirement`/`--constraint` reference | `range: Range` (target text only), `target: String` (raw, unresolved) |
| `ParseResult::document_links` (new field, `deps-pypi::parser`) | Collected `RequirementRef`s for a parsed file | `Vec<RequirementRef>`, empty unless the file was kept (`keep == true`) |
| `Ecosystem::generate_document_links` (new trait method, `deps-core`) | Produces LSP `DocumentLink`s from a parse result; default returns `Vec::new()` | Only `PypiEcosystem` overrides it as of this PR |
| `Ecosystem::manifest_directory_patterns` (new trait method, `deps-core`) | Declares `(directory_name, suffix)` pairs an ecosystem recognizes via directory-layout convention | Default empty; PyPI declares `[("requirements", ".txt")]` |
| `PypiParser::parse_requirements` (changed signature) | Gained a `require_strong_signal: bool` parameter | `true` when routed via `manifest_directory_patterns` fallback, `false` for a primary basename match |
| `handle_document_link` (new handler, `deps-lsp::handlers::document_link`) | `textDocument/documentLink` request handler, ecosystem-trait delegation, no registry/network access | Loads the document, reads cached parse result, delegates to `Ecosystem::generate_document_links` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `-r`/`-c` target already a URL (`https://...`) | Left unresolved — not joined onto the filesystem directory, no `DocumentLink` produced for it (only local relative/absolute paths are resolved) |
| Bare `-r` with no target text after it | No `RequirementRef` recorded — `extract_option_target` returns `None` |
| Option other than `-r`/`-c`/`--requirement`/`--constraint` (e.g. `--index-url`, `-e`, `--pre`) | Never produces a document link, even though it is a recognized/strong-signal option for the parse-keep gate |
| Target contains a bidi override or zero-width character | Rejected per FR-003; `warn_rejected_value` logs it; no crash, no partial link |
| `requirements/introduction.txt` (prose file with bare-word lines resembling PEP 508 names, e.g. "Introduction", "Scope") | Directory-pattern-routed, `require_strong_signal: true` gate drops the ratio-based keep-arm; file yields zero dependencies, no live PyPI lookup |
| `requirements/base.txt` with a genuine pip option or version-pinned line | Strong-signal check alone keeps it — `require_strong_signal` only removes the *ratio* arm, not the strong-signal arm |
| Windows path separator mismatch between `Uri::to_file_path` (forward slashes) and `Path::join` (native `\`) | Tooltip is derived by round-tripping through the resolved `target_uri.to_file_path()`, not the raw joined `target_path`, so tooltip and target stay consistent |

## 7. Success Criteria

| ID | Metric | Target (verified) |
|----|--------|--------------------|
| SC-001 | `-r`/`-c`/`--requirement`/`--constraint` targets produce a correctly-ranged documentLink | Covered by `test_document_links_short_form`, `test_document_links_long_form_space_separated`, `test_document_links_long_form_equals_separated`, `test_document_links_range_slices_to_target_text_only` (`crates/deps-pypi/src/parser/requirements.rs`) |
| SC-002 | Unrelated/known options never produce a link; a bare option with no target is skipped | Covered by `test_document_links_ignores_unrelated_options`, `test_document_links_bare_option_with_no_target_is_skipped` |
| SC-003 | End-to-end `textDocument/documentLink` handler resolves a real reference to a file URI | Covered by `test_handle_document_link_requirements_reference` (`crates/deps-lsp/src/handlers/document_link.rs`) |
| SC-004 | `requirements/*.txt` directory layout is recognized; unrelated directories/suffixes are not | Covered by `test_get_for_uri_directory_pattern_matches_split_requirements_layout`, `test_get_for_uri_directory_pattern_requires_matching_directory_and_suffix` (`crates/deps-core/src/ecosystem_registry.rs`) |
| SC-005 | Directory-pattern-only routing does not misclassify prose as a manifest; genuine manifests under the same layout still parse | Covered by `test_strict_gate_drops_prose_that_would_survive_ratio_gate`, `test_strict_gate_still_keeps_file_with_real_pip_option`, `test_strict_gate_still_keeps_file_with_version_specifier` (`crates/deps-pypi/src/parser/requirements.rs`) |
| SC-006 | Zero regression for root-level `requirements.txt`/`constraints.txt` | `test_constraints_txt_parses_identically` and the full pre-existing `deps-pypi` suite pass unmodified with the new `require_strong_signal` parameter threaded as `false` |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `prefix_suffix_matches`/`manifest_pattern_matches` for any future
  basename/directory/lockfile wildcard matching rather than re-deriving
  the `starts_with`/`ends_with`/length check.
- Route any new PyPI file-reference feature through
  `Ecosystem::generate_document_links` rather than a PyPI-specific
  handler bypassing the trait.
- Apply FR-003's rejected-character set to any other future
  user-controlled, click-through target this project introduces
  (consistent security posture across handlers).

### Ask First
- Extending `manifest_directory_patterns` to a second PyPI directory
  convention, or to another ecosystem, beyond `requirements/*.txt` —
  confirm the false-positive risk profile first (per FR-006's rationale).
- Resolving `-r`/`-c` targets that are themselves absolute filesystem
  paths outside the workspace root (not exercised by the shipped tests).

### Never
- Construct a `DocumentLink` from an unvalidated target string — FR-003's
  check must run before any URI/tooltip is built, not after.
- Loosen the `require_strong_signal` gate for directory-pattern-routed
  files back to the ratio-based arm — that regresses the exact
  misclassification (#452 S6) this PR closed.

## 9. Open Questions

None — this spec documents already-shipped, tested work. No
`[NEEDS CLARIFICATION]` items remain open.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[009-pypi-requirements-txt/spec|Support requirements.txt (pip family) in deps-pypi]] — the original feature spec this builds on
- [[027-nuget-unlisted-version-and-multiproject-lockfile/spec|NuGet unlisted-version hover marker and multi-project lock file matching]] — the sibling half of the same PR (#458), covering the `deps-nuget` gaps (issue #451)
- `crates/deps-pypi/src/parser/requirements.rs` — `-r`/`-c` parsing, `extract_option_target`, `require_strong_signal` gate
- `crates/deps-pypi/src/ecosystem.rs` — `generate_document_links`, `is_safe_document_link_target`, `matched_only_via_directory_pattern`
- `crates/deps-lsp/src/handlers/document_link.rs` — `handle_document_link`
- `crates/deps-core/src/ecosystem_registry.rs` — `get_for_directory_pattern`, `manifest_pattern_matches`, `lockfile_pattern_matches`, `prefix_suffix_matches`
- Issue #452 — the tracked TODO(critic) gap this spec documents
- PR #458, commit `e6a67e77` — shipped implementation

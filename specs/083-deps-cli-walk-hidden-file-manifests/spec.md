---
aliases:
  - Hidden-file manifest discovery
  - Root .gitlab-ci.yml walk gap
  - deps-cli walk hidden files
tags:
  - sdd
  - spec
  - bug
  - deps-cli
  - security
  - ci-gate
  - gitlab-ci
created: 2026-10-07
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[030-gitlab-ci-ecosystem/spec|030 GitLab CI ecosystem]]"
  - "[[065-cli-check-symlink-manifest-walk/spec|065 CLI check symlink manifest walk]]"
---

# Feature: deps-cli directory walk discovers hidden-file manifests (root `.gitlab-ci.yml`)

> [!info] Metadata
> **Author**: continuous-improvement cycle (spec session, 2026-10-07)
> **Branch**: N/A (no implementation branch yet; suggested `fix/hidden-file-manifest-walk`)
> **Priority**: P1
> **Category**: bug (label: `bug`)
> **Issue**: [NEEDS CLARIFICATION: GitHub issue number not supplied with the finding]
> **Class**: same fail-open class as #1108 and #1109 (a CI security gate silently reports zero findings)

## 1. Overview

### Problem Statement

`deps-cli check <dir>` discovers manifests by walking the directory with `ignore::WalkBuilder` and
`.hidden(true)` (`crates/deps-cli/src/walk.rs`, `walk_directory` called with `DotDirs::Skip`). The `ignore` crate's
hidden filter matches every dot-prefixed basename, files and directories alike. The code compensates for hidden
**directories** only: `hidden_ecosystem_directories` derives dot-directory names (`.github`, `.gitlab`) from every
registered ecosystem's `manifest_directory_patterns()` and re-walks each with hidden lifted (`DotDirs::Descend`).

Nothing compensates for a hidden **file** declared through `manifest_filenames()`. Today the only one is GitLab CI's
`.gitlab-ci.yml` (`crates/deps-gitlab-ci/src/ecosystem.rs`, `manifest_filenames`). The hidden filter drops it before
`route_file` or the registry ever sees it, in the root directory and in every nested directory.

Observed live at HEAD `8cb71b132` with a debug build (re-verified while writing this spec):

| Layout | `deps-cli check <dir>` result |
|--------|-------------------------------|
| `.gitlab-ci.yml` only | `warning: no manifests were discovered under the given path(s)`, `No findings.`, exit 2 |
| `.gitlab-ci.yml` plus `Cargo.toml` | `No findings.`, **exit 0**, no warning |
| `.gitlab-ci.yml` explicit path | findings reported (the file parses fine) |
| `.gitlab/ci/x.yml` (hidden directory) | findings reported |

The mixed layout is the dangerous one. A repository with any other manifest suppresses the "zero manifests" guard added
for #1108, so the GitLab pipeline's unpinned or mutable `include:` refs and its image tags are never scanned. A CI
security gate (`git checkout && deps-cli check .`) reports success. The only-manifest layout exits non-zero, but the
message blames a wrong root or routing problem, not a skipped file. The root `.gitlab-ci.yml` is the canonical and by far
most common GitLab CI location, so this is not an edge case.

> [!bug] Why the existing design misses it
> Hidden-ness is handled by two disjoint mechanisms: a blanket skip for the main walk, and a registry-derived lift for
> directories only. No registry-derived mechanism exists for hidden files. A future ecosystem declaring any
> dot-prefixed manifest filename (for example `.pre-commit-config.yaml` in the unshipped spec 044) would hit the
> same gap silently.

### Goal

A directory walk discovers a hidden-file manifest exactly as it discovers a non-hidden one, in the walk root and in
every nested directory. Eligibility is derived from the live ecosystem registry, never from a hardcoded name, and the
skip-hidden protection still keeps `.git` and every other non-ecosystem dot-entry out of the walk.

### Out of Scope

- Changing `.gitignore`/`.ignore` semantics, `PRUNED_DIRECTORIES`, the symlink policy, or the walk-entry cap.
- The LSP server (`deps-lsp`). Editors open a file explicitly, so routing already works there.
- Reworking the hidden-**directory** mechanism (`hidden_ecosystem_directories`). It stays as is unless the plan chooses
  to fold it into the new mechanism (see Open Questions).
- Accepting `.gitlab-ci.yaml`. GitLab does not recognize it, per spec 030 FR-001.
- Hidden files that no ecosystem claims (`.env`, `.eslintrc.json`, `.DS_Store`, ...). They stay skipped.
- Changing the zero-manifests exit-code or warning behavior (#1108).

## 2. User Stories

### US-001: GitLab CI repository gated in CI
AS A maintainer running `deps-cli check .` as a CI security gate on a repository whose pipeline is a root `.gitlab-ci.yml`
I WANT the walk to discover that file
SO THAT mutable or unpinned `include:`/`image:` refs fail the gate instead of passing silently

**Acceptance criteria:**
```
GIVEN a directory containing a root .gitlab-ci.yml with a tag-pinned project include and a Cargo.toml
WHEN deps-cli check <dir> runs
THEN the .gitlab-ci.yml is among the discovered manifests
AND its findings appear in the report with display path ".gitlab-ci.yml"
```

### US-002: Monorepo with nested GitLab pipelines
AS A monorepo maintainer with `services/api/.gitlab-ci.yml`
I WANT nested hidden-file manifests discovered at any depth
SO THAT every service's pipeline is gated, not only the repository root's

**Acceptance criteria:**
```
GIVEN sub/.gitlab-ci.yml two directories below the walk root
WHEN deps-cli check <root> runs
THEN the file is discovered with display path sub/.gitlab-ci.yml
```

### US-003: A future ecosystem with a hidden manifest filename
AS A contributor adding an ecosystem whose manifest basename starts with a dot
I WANT the walk to pick it up from `manifest_filenames()` alone
SO THAT I never have to edit `walk.rs`, and the registry stays the only source of truth for routing

**Acceptance criteria:**
```
GIVEN a registry containing a test ecosystem whose manifest_filenames() is [".custom-manifest.toml"]
WHEN the walk runs over a directory containing that file and a .env file
THEN .custom-manifest.toml is discovered
AND .env is not
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a directory walk visits a regular file whose basename starts with `.` and is claimed by a registered ecosystem's routing THE SYSTEM SHALL route it exactly as it routes a non-hidden manifest of the same ecosystem. | must |
| FR-002 | THE SYSTEM SHALL decide which hidden files are eligible by querying the live `EcosystemRegistry` (the same way `hidden_ecosystem_directories` does for directories), and SHALL NOT contain a hardcoded hidden-filename list. | must |
| FR-003 | WHEN a walk root contains `.gitlab-ci.yml` directly THE SYSTEM SHALL discover it (the reported repro). | must |
| FR-004 | WHEN `.gitlab-ci.yml` exists in a nested directory (not hidden, not pruned) THE SYSTEM SHALL discover it. | must |
| FR-005 | THE SYSTEM SHALL continue to exclude from the directory walk every dot-prefixed file that no registered ecosystem claims, and every dot-prefixed directory except those named by a registered ecosystem's `manifest_directory_patterns`. | must |
| FR-006 | THE SYSTEM SHALL continue to never descend into `.git`, `.hg`, `.svn`, `.bzr` or any other `PRUNED_DIRECTORIES` entry, whatever the hidden-file eligibility rules say. | must |
| FR-007 | WHEN a hidden-file manifest is a symlink THE SYSTEM SHALL apply the existing `SymlinkPolicy` classification and root-containment rules unchanged (reported via `ignored_manifests`, `broken_manifest_symlinks`, or routed under `--follow-symlinks`). | must |
| FR-008 | WHEN `GitignorePolicy::Respect` is active and a hidden-file manifest is excluded by an ignore rule THE SYSTEM SHALL report it through `WalkOutcome::ignored_manifests`, like any other manifest-shaped file. The detection walk in `detect_ignored_manifests` must therefore see hidden-file manifests too. | must |
| FR-009 | WHEN `GitignorePolicy::Ignore` (the `check` default) is active THE SYSTEM SHALL NOT let a `.gitignore` or `.ignore` file remove a hidden-file manifest from the scan (#1109 invariant). | must |
| FR-010 | THE SYSTEM SHALL count each hidden-file manifest visited against `MAX_WALKED_FILES` exactly like any other walked entry. | must |
| FR-011 | THE SYSTEM SHALL keep `deps-cli check <path-to-.gitlab-ci.yml>` (explicit file) behavior unchanged. | must |
| FR-012 | THE SYSTEM SHALL leave `.gitlab/ci/*.yml` discovery (hidden-directory path) behavior unchanged, with no manifest reported twice. | must |
| FR-013 | WHEN the same walk is used by `deps-cli update` THE SYSTEM SHALL behave identically (one shared `walk::walk`). | should |

> [!question] Eligibility scope: filename only, or full routing?
> The finding speaks of hidden-file `manifest_filenames()` entries. `manifest_patterns()` and `manifest_extensions()`
> can also match a dot-prefixed basename (for example a file named `.csproj`, or `.x.csproj`). See Open Question 1.

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | The gate must fail closed for GitLab CI: no layout of a root or nested `.gitlab-ci.yml` may yield a report that omits it without a non-zero exit or a visible warning. |
| NFR-002 | Type safety | No stringly-typed or catch-all workaround. Eligibility is expressed as a typed value derived from the registry (for example a newtype or a predicate built once per walk). The existing `DotDirs` enum keeps its exhaustive-match property, and no `_ =>` arm is added to sidestep it. |
| NFR-003 | Consistency | The mechanism lives in one place in `walk.rs` and is derived from the same registry API the directory mechanism uses. No per-ecosystem special case in `deps-cli`. |
| NFR-004 | Performance | No additional full-tree traversal. Discovery must not double the walk cost for the common case (see Open Question 3). |
| NFR-005 | Robustness | The change must not widen what an attacker-controlled tree can make the walk read: only files already routable by the registry are admitted. |
| NFR-006 | Testability | Regression coverage in `walk.rs`'s `mod tests` in the style of the #1165 test (a test that fails if the wiring is flipped back). |

## 5. Data Model

No new persisted data.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Hidden-file eligibility | A per-walk value derived once from the `EcosystemRegistry`. Answers: may this dot-prefixed file basename enter the walk? | built from `manifest_filenames()` (and possibly patterns/extensions, see Open Question 1) |
| `DotDirs` | Existing `Skip`/`Descend` enum selecting `WalkBuilder::hidden`. | may gain a third variant or be paired with the eligibility value, per plan |
| `WalkOutcome` | Unchanged. | `manifests`, `ignored_manifests`, `walk_errors`, `truncated`, ... |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Root `.gitlab-ci.yml` and root `Cargo.toml` | Both discovered; GitLab findings reported (was: silently omitted, exit 0). |
| Only root `.gitlab-ci.yml` | Discovered; findings reported; no "no manifests" warning. |
| `.gitlab-ci.yml` in a nested directory | Discovered with a relative display path. |
| `.gitlab-ci.yml` inside `.git/` | Never reached (`.git` is pruned). |
| `.gitlab-ci.yml` inside `node_modules/` or `vendor/` | Still pruned; the existing pruned-directory-manifest warning applies unchanged (a manifest directly at the root of a pruned directory is reported via `ignored_manifests`). |
| `.gitlab-ci.yml` inside a non-ecosystem hidden directory (for example `.cache/.gitlab-ci.yml`) | Not discovered. The hidden directory is still skipped (FR-005). [NEEDS CLARIFICATION: confirm this is the wanted behavior; see Open Question 4.] |
| `.gitlab-ci.yml` inside `.gitlab/` or `.github/` sub-walk | Discovered once, not twice (FR-012). |
| `.gitlab-ci.yml` listed in `.gitignore`, `GitignorePolicy::Ignore` | Still discovered (FR-009). |
| `.gitlab-ci.yml` listed in `.gitignore`, `GitignorePolicy::Respect` | Excluded and reported via `ignored_manifests` (FR-008). |
| `.gitlab-ci.yml` is a broken symlink | Reported via `broken_manifest_symlinks`, unchanged (FR-007). |
| `.gitlab-ci.yml` is a symlink to a file outside the root | Never routed; reported via `ignored_manifests` (FR-007). |
| `.gitlab-ci.yml` is a directory | Not a file; no manifest, no crash. |
| Hidden file `.env` / `.DS_Store` | Skipped (FR-005). |
| `MAX_WALKED_FILES` reached | `truncated` set as today (FR-010). |
| Registry with no hidden-file manifest names | Behavior identical to today (empty eligibility set). |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | The four-row repro table in Section 1 re-run against the fixed build | root and nested `.gitlab-ci.yml` discovered in 100% of layouts; mixed layout reports GitLab findings |
| SC-002 | Hardcoded hidden-filename literals added to `walk.rs` | 0 |
| SC-003 | Existing `walk.rs` and `deps-cli` tests | all pass unchanged; the only edits are added tests |
| SC-004 | New regression tests | at least: root file, nested file, non-claimed hidden file stays skipped, `.git` content stays out, registry-derived (test ecosystem) case, `Respect` mode ignored-manifest report |
| SC-005 | Live end-to-end verification (project rule: no conclusions from code reading alone) | repro steps 1 to 4 from the finding pass on a debug build |

## 8. Agent Boundaries

### Always (without asking)
- Reproduce with the live binary before and after the fix (`deps-cli check` on the repro layouts).
- Add the regression tests to `crates/deps-cli/src/walk.rs`'s `mod tests` in the #1165 style, documenting which wiring each pins.
- Derive hidden-file eligibility from `EcosystemRegistry`, reusing the registry API that `hidden_ecosystem_directories` already uses.
- Run `cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, and the strict rustdoc gate from `.claude/rules/branching.md`.
- Update the `walk` rustdoc (the "walked twice" paragraph), `CHANGELOG.md` `[Unreleased]` (one line plus PR link), and the CI-testing knowledge base entries (`.local/testing/coverage.md`, `playbooks/gitlab-ci.md`, `regressions.md`) per `.claude/rules/branching.md`.

### Ask First
- Changing the `Ecosystem` trait (for example adding a `hidden_manifest_filenames()` method). It is a sealed trait in `deps-core`; prefer deriving from the existing methods.
- Extending eligibility beyond exact `manifest_filenames()` (Open Question 1).
- Changing the exit-code or warning behavior of the zero-manifests guard.
- Folding `hidden_ecosystem_directories` into the new mechanism (Open Question 2).

### Never
- Hardcode `".gitlab-ci.yml"` (or any ecosystem filename) in `walk.rs`.
- Switch the main walk to `hidden(false)` with no replacement filter. That would descend into `.git`, `.cache`, `.idea` and every other dot-directory.
- Add a catch-all `_ =>` arm or a stringly-typed escape hatch to sidestep the typed design.
- Let `.gitignore`/`.ignore` affect discovery under `GitignorePolicy::Ignore`.
- Edit `crates/deps-zed` or any source outside the scope of this fix in the same commit.
- Fix this in a `deps-cli check` session of the continuous-improvement cycle. Implementation goes through `/rust-team`.

## 9. Open Questions

- [NEEDS CLARIFICATION 1: Eligibility scope. (a) Admit a hidden file iff `registry.for_filename(basename)` is `Some`, so exact names, patterns and extensions share the single routing truth (recommended: no second matcher to drift, mirrors `is_manifest_shaped_by_name`); or (b) only exact `manifest_filenames()` entries that start with `.` (literal reading of the finding). Option (a) also admits a hidden `.x.csproj`. Is that acceptable?]
- [NEEDS CLARIFICATION 2: Mechanism. Candidate designs for the plan: (i) main walk with `hidden(false)` plus a `filter_entry` that rejects dot-prefixed directories (except the registry-derived ecosystem ones) and dot-prefixed files not eligible; (ii) keep `hidden(true)` and add a registry-derived second pass over hidden files only; (iii) `ignore::overrides` whitelist globs. (iii) looks unsuitable because a whitelist override makes every non-matching file ignored; this must be confirmed against the pinned `ignore` version before the plan commits. Which design, and should (i) also absorb `hidden_ecosystem_directories` so there is one mechanism?]
- [NEEDS CLARIFICATION 3: Does the chosen design change entry counting against `MAX_WALKED_FILES` for repositories with many dot-entries (for example a large `.cache` now yielding entries under design (i) before the filter rejects them)? Needs a measurement, not an assumption.]
- [NEEDS CLARIFICATION 4: Hidden file inside a non-ecosystem hidden directory (`.cache/.gitlab-ci.yml`, `.idea/...`) stays unscanned by FR-005. Confirm.]
- [NEEDS CLARIFICATION 5: `detect_ignored_manifests` also takes a `hidden: bool` (the inverse-bool convention `DotDirs` replaced in #1135). Should it be converted to the same typed eligibility value in this fix, or left for a follow-up? Leaving it would make FR-008 incomplete.]
- [NEEDS CLARIFICATION 6: The finding reports "exit 0" for the sole-manifest layout. At HEAD the sole-manifest layout exits 2 (the #1108 guard) and only the mixed layout exits 0. The spec follows the observed behavior. Should the issue text be corrected?]
- [NEEDS CLARIFICATION 7: GitHub issue number to link in the MOC row and `Closes #N`.]

> [!question] Verification note
> Open Questions 2 and 3 assert behavior of the `ignore` crate from memory. Per the project's live-testing principle, the
> plan phase must verify them against the pinned crate source (see the memory note on verifying security claims
> empirically) before they are used as design constraints.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[030-gitlab-ci-ecosystem/spec|030 GitLab CI ecosystem]] — declares `.gitlab-ci.yml` (FR-001) and the `.gitlab/ci` directory pattern
- [[065-cli-check-symlink-manifest-walk/spec|065 CLI check symlink manifest walk]] — symlink handling in the same walk
- `crates/deps-cli/src/walk.rs` — `walk_with_limit`, `walk_directory`, `hidden_ecosystem_directories`, `detect_ignored_manifests`, regression test for #1165
- `crates/deps-gitlab-ci/src/ecosystem.rs` — `manifest_filenames` (`.gitlab-ci.yml`) and `manifest_directory_patterns`
- `crates/deps-core/src/ecosystem_registry.rs` — `for_filename`, `for_uri`
- Related issues in the same fail-open class: #1108 (relative root yielded zero manifests), #1109 (`.gitignore` removed manifests from a CI gate), #1135 (`DotDirs` typed replacement for the inverse bool), #1165 (`DotDirs::Descend` regression test)

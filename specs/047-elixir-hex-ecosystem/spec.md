---
aliases:
  - Elixir Hex Ecosystem
  - mix.exs Dependency Version Hints
tags:
  - sdd
  - spec
  - research
  - ecosystem/hex
  - new-ecosystem
  - priority/p4
created: 2026-09-05
status: draft
related:
  - "[[MOC-specs]]"
  - "[[004-release-freshness-signal/spec]]"
  - "[[002-osv-vulnerability-diagnostics/spec]]"
---

# Feature: New ecosystem — Elixir Hex (`mix.exs` dependency version hints)

> [!info] Metadata
> **Author**: continuous-improvement research cycle (ci-045, 2026-09-05) — a candidate first
> recorded in `.local/testing/playbooks/competitive-parity.md`'s Known Gaps table since cycle
> 026 (2026-09-03), re-confirmed unfiled in cycles 028, 029, and 036 (each time deferred in
> favor of a higher-evidence finding that cycle), acted on now because cycle 045 has no
> stronger-evidenced dependency/research finding pending (`cargo outdated --workspace` and
> `cargo deny check advisories` both clean; recent PRs #631/#635/#637/#638/#639 checked for
> orphaned deferred-follow-up notes, none found).
> **Branch**: [NEEDS CLARIFICATION: no tracking issue filed yet — assign issue number before
> branching, e.g. `feat/<issue>-elixir-hex-ecosystem`]
> **Type**: research / new ecosystem

## 1. Overview

### Problem Statement

deps-lsp currently supports 14 package ecosystems (Cargo, npm, Deno, PyPI, Go, Bundler, Dart,
Maven, Gradle, Swift, Composer, NuGet, GitHub Actions, GitLab CI/CD) but has zero Elixir/Hex
support — confirmed this cycle via `grep -rli "elixir\|hex.pm\|mix.exs" crates/` returning no
hits anywhere in the workspace. Elixir projects declare dependencies in `mix.exs` (Elixir's
package manager, Mix, resolving packages from the `hex.pm` registry), e.g.:

```elixir
defp deps do
  [
    {:jason, "~> 1.4"},
    {:phoenix, "== 1.7.14"},
    {:ecto, github: "elixir-ecto/ecto"}
  ]
end
```

Elixir developers editing `mix.exs` get no in-editor signal — no hover showing current vs.
latest version, no outdated-dependency diagnostic, no completion, no update code action —
even though the underlying data (hex.pm's public API) is freely and keylessly available, the
same class of "outdated/unknown/deprecated dependency" signal deps-lsp already provides for
every other ecosystem it supports.

### Demand Signal

Three independent, actively-maintained reference projects already support this ecosystem —
clearing this project's own "2+ reference projects" evidentiary bar used elsewhere in
`specs/` to justify new-ecosystem work (see e.g. [[030-gitlab-ci-ecosystem/spec]] and
[[042-docker-base-image-ecosystem/spec]]'s framing of prior-art coverage as a demand signal):

- **GitHub Dependabot** has native `hex` ecosystem support (Elixir/Mix) — first-party, not a
  third-party/alpha integration (unlike some other candidates this project has weighed, e.g.
  `dependabot-gitlab`).
- **Renovate** has a mature `mix` manager, not an experimental/niche one.
- **`filllabs/dependi`** (the closest tracked competitor, a VS Code extension) shipped Elixir
  Hex support (v0.7.25) by direct user request (`filllabs/dependi#243`, now closed/shipped
  there).

Additionally: **ElixirLS** (the standard Elixir language server) has no dependency-freshness
or version-hint capability at all. Unlike most new-ecosystem candidates this project has
spec'd, which catch up to editor extensions covering an already-served niche, this would be a
**first-mover in-editor experience** for the Elixir ecosystem specifically — no existing LSP
server for Elixir provides this signal today.

### Live-Verified API Research

Both endpoints below were exercised this session with real HTTP requests against `phoenix`,
`jason`, and `ecto` packages — not assumed from documentation:

- `GET https://hex.pm/api/packages/{name}` — keyless, publicly reachable. Returns the full
  release list (version + `inserted_at` timestamp per release, sorted newest-first) plus
  repository/license/owner metadata. The per-release `inserted_at` timestamp is directly
  reusable by [[004-release-freshness-signal/spec|the release-freshness signal feature]]
  (issue #145) without any new timestamp-sourcing logic.
- `GET https://hex.pm/api/packages/{name}/releases/{version}` — richer per-release data than
  most registries this project already integrates:
  - `retirement` — null when the release is not retired; populated with a retirement
    reason/message when a maintainer marks a release unsafe/deprecated/security-flawed/
    renamed/other. This is Hex's own first-class retirement mechanism — more explicit and
    more structured than npm's bare `deprecated` string or PyPI's `projectStatus`.
  - `security_advisories[]` — empty array when the release has no known advisory
    [NEEDS CLARIFICATION: the populated (non-empty) shape of this field was not verified this
    session, since no test package with a live advisory was checked — needs verification
    against a known-vulnerable Hex package before `/sdd plan`].
  - `requirements{}` — the package's own dependency tree; potentially useful context, not
    required for an MVP implementation.

### Version Syntax — a Structurally Different Manifest Format

Mix dependencies are Elixir tuples inside a function body, not a declarative TOML/JSON/YAML
document like every other ecosystem this project currently parses:

```elixir
{:jason, "~> 1.4"}
{:phoenix, "== 1.7.14"}
{:ecto, github: "elixir-ecto/ecto"}          # git dep — out of scope, see below
{:credo, "~> 1.7", only: [:dev, :test], runtime: false}
```

`mix.exs` itself is a regular `.ex` Elixir source file (typically a `defp deps do [...] end`
function returning a list) — this project has no existing precedent for parsing a
general-purpose programming-language source file as a manifest; every other supported
ecosystem's manifest is a declarative data format. Whether to regex/line-scan over the literal
tuple syntax (mirroring how simple, tolerant parsing is already used elsewhere in this
project for constrained syntactic subsets) or reach for a small purpose-built tokenizer over
Elixir's tuple/keyword-list grammar is a first-class open design question left for `/sdd
plan` — **not resolved in this specify-phase document**, per this project's research-spec
convention of separating WHAT/WHY from HOW.

Hex's `~>` ("pessimistic operator") is structurally analogous to `crates/deps-bundler`'s
already-supported RubyGems `~>` operator (both are called "pessimistic version constraint" in
their respective ecosystems' own documentation), but this project's own
`crates/deps-bundler/src/formatter.rs` implementation must not be
assumed to be semantically identical without verification — Hex's `~>` handles 2-segment
requirements differently in at least one documented edge case (`~> 2.0` on Hex allows any
`2.x`, matching Bundler's `~> 2.0` behavior, but `~> 2.0.0` on Hex constrains only the patch
segment exactly as Bundler's 3-segment form does) — this needs an explicit side-by-side
semantic comparison in `/sdd plan`, not a blind copy of the Bundler implementation.

`only: :dev`, `only: [:dev, :test]`, and other keyword options (e.g. `runtime: false`,
`override: true`) can appear after the version-requirement string in the same tuple and must
not be misparsed as part of the requirement itself.

### Goal

deps-lsp detects `mix.exs`, parses the dependency tuple list, extracts each entry's package
name and version-requirement string (skipping git-sourced deps for version-hint purposes, the
same treatment already given to git-sourced dependencies in Cargo and npm), resolves version
data via the hex.pm public API, and surfaces the same feature set this project delivers for
every other ecosystem: hover (current vs. latest version, license), completion (version
list), diagnostics (outdated / unknown / retired-equivalent via `retirement`, and potentially
vulnerability-equivalent via `security_advisories[]`), code actions (update to latest), code
lens, and inlay hints — consistent in behavior with all 14 existing ecosystems per this
project's cross-ecosystem-consistency rule (`.claude/rules/continuous-improvement.md`).

### Out of Scope

- **Git-sourced dependencies** (`{:ecto, github: "elixir-ecto/ecto"}`, or `git:`/`path:`
  keyword forms) — not version-hintable via hex.pm, same treatment as git deps in
  `deps-cargo`/`deps-npm` today: recognized and skipped, not resolved.
- **Umbrella projects** (multiple `mix.exs` files under `apps/*/mix.exs` in one repository, an
  Elixir-specific project layout) — see Open Questions.
- **`mix.lock` in-use-version resolution** — this spec covers manifest-level hover/diagnostics
  only; lock-file-driven "in-use version" detection (this project's `LockFileProvider`
  pattern, `deps-core::lockfile`) is a plausible fast-follow, not part of this spec's MVP
  scope.
- **`requirements{}` (transitive dependency tree) surfaced from the hex.pm releases
  endpoint** — noted as available context data but not required for MVP hover/diagnostics.
- **Full Elixir expression evaluation** (e.g. `deps` computed via `if`/`case`/function calls
  rather than a literal list) — phase 1 targets the common literal-list-of-tuples form; a
  computed/conditional deps list is out of scope and should degrade gracefully (no crash, no
  false diagnostic), not attempt general-purpose Elixir evaluation.

## 2. User Stories

### US-001: See outdated Hex dependency versions in-editor

AS A Elixir developer editing `mix.exs`
I WANT to see at a glance which dependencies have a newer version available on hex.pm
SO THAT I can decide whether to bump a dependency without leaving the editor to check hex.pm's
package page manually.

**Acceptance criteria:**
```
GIVEN a mix.exs with a deps function containing one or more {:package, "requirement"} tuples
      resolving to a real hex.pm package
WHEN the editor requests hover over a dependency tuple
THEN the server SHALL show:
     - The current version requirement
     - The latest available version on hex.pm
     - Whether the current requirement is satisfied by an outdated release
     - License information (from the hex.pm package metadata)
```

### US-002: Retired releases are flagged distinctly from ordinary outdated releases

AS A Elixir developer
I WANT a retired Hex release (Hex's own maintainer-driven retirement mechanism) to be flagged
distinctly from an ordinary "newer version available" diagnostic
SO THAT I understand a maintainer has explicitly marked my pinned version unsafe, deprecated,
or superseded — not just old.

**Acceptance criteria:**
```
GIVEN a mix.exs dependency whose currently-pinned/resolved version has a non-null
      `retirement` field on the hex.pm releases endpoint
WHEN the server generates diagnostics for that dependency
THEN a distinct retirement diagnostic SHALL be produced, including the retirement reason and
     message returned by the API, separate from the ordinary "outdated version" diagnostic
```

### US-003: Git-sourced and umbrella-app dependencies do not produce false diagnostics

AS A Elixir developer whose `mix.exs` mixes hex.pm-sourced deps with `github:`/`git:`/`path:`
deps
I WANT the non-Hex-sourced entries left alone entirely
SO THAT I don't get nonsensical "unknown package" diagnostics on dependencies that were never
meant to resolve against hex.pm.

**Acceptance criteria:**
```
GIVEN a mix.exs deps list containing a mix of hex.pm-sourced tuples and
      github:/git:/path:-sourced tuples
WHEN the server parses the file
THEN git/path-sourced entries SHALL be recognized and excluded from registry resolution and
     diagnostics entirely; hex.pm-sourced entries SHALL be processed normally
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect `mix.exs` by filename and register it as a manifest document, routed through the existing LSP document-lifecycle handlers | must |
| FR-002 | THE SYSTEM SHALL parse the `deps` function body's list of dependency tuples and, for each entry, extract the package name (atom, e.g. `:jason`) and the version-requirement string (e.g. `"~> 1.4"`) when present | must |
| FR-003 | THE SYSTEM SHALL recognize `github:`, `git:`, and `path:` keyword-option tuples as non-Hex-resolvable and exclude them from registry resolution and diagnostics entirely, with no error or false diagnostic | must |
| FR-004 | THE SYSTEM SHALL correctly separate a tuple's version-requirement string from trailing keyword options (`only:`, `runtime:`, `override:`, etc.) without misinterpreting an option as part of the requirement | must |
| FR-005 | THE SYSTEM SHALL resolve package version data via `GET https://hex.pm/api/packages/{name}` (keyless, no new auth surface) | must |
| FR-006 | THE SYSTEM SHALL resolve per-release detail (including `retirement` and `security_advisories[]`) via `GET https://hex.pm/api/packages/{name}/releases/{version}` for the version(s) needed to render hover/diagnostics | must |
| FR-007 | THE SYSTEM SHALL implement Hex's `~>` pessimistic-operator semantics for version-requirement satisfaction, verified independently against Hex's own documented semantics rather than assumed identical to `deps-bundler`'s `~>` implementation | must |
| FR-008 | THE SYSTEM SHALL produce an outdated-version diagnostic when a resolvable dependency's satisfied version is behind the latest release on hex.pm, consistent in severity mapping and wording conventions with existing ecosystems | must |
| FR-009 | WHEN a dependency's resolved release has a non-null `retirement` field THE SYSTEM SHALL produce a distinct retirement diagnostic surfacing the retirement reason/message, separate from the ordinary outdated-version diagnostic | must |
| FR-010 | THE SYSTEM SHALL expose hover content showing current requirement, latest available version, and license (from package metadata) for each resolvable dependency | must |
| FR-011 | THE SYSTEM SHALL implement `generate_completions` (no default exists on the `Ecosystem` trait) offering the version list for a dependency's requirement string, reusing `deps_core::completion::complete_versions_generic` if its input shape fits Hex's version list | must |
| FR-012 | THE SYSTEM SHALL expose a code action offering to update a dependency's version requirement to the latest hex.pm release, applied as a `WorkspaceEdit`, following this project's existing update-action pattern | must |
| FR-013 | THE SYSTEM SHALL produce equivalent hover/diagnostic/completion/code-lens/inlay-hint behavior across all `mix.exs` instances and all resolvable dependency entries, per the project's cross-ecosystem-consistency rule | must |
| FR-014 | WHEN a `mix.exs` deps list is not a literal list of tuples (e.g. computed via a function call or conditional) THE SYSTEM SHALL degrade gracefully — log a debug-level note and return no diagnostics for that file — rather than attempting general Elixir expression evaluation or crashing | must |
| FR-015 | WHEN the hex.pm API is unreachable or returns an error status THE SYSTEM SHALL degrade gracefully using this project's established cached-data-fallback pattern, consistent with every other registry client | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | New dependency crate | This ecosystem SHALL be implemented as its own crate (`deps-hex`), following the project's Simplicity principle and the precedent of small existing ecosystem crates (`deps-cargo`, `deps-github-actions`) |
| NFR-002 | No new HTTP client stack | Registry access SHALL reuse the workspace's existing HTTP client conventions (`reqwest` with `rustls`, existing `HttpCache`-backed conditional-request caching pattern) — no new HTTP library introduced |
| NFR-003 | Reliability | When hex.pm is unreachable or rate-limited, the system SHALL degrade gracefully: cached data served if available; otherwise an informational/loading state, never a false "outdated" or "unknown package" positive |
| NFR-004 | Consistency | Hover format, diagnostic wording, inlay-hint presentation, and code-action wording SHALL be structurally consistent with existing ecosystems, adapted only where Hex-specific concepts (`retirement`, `~>` semantics) genuinely differ, per the cross-ecosystem-consistency rule |
| NFR-005 | Parsing robustness | The `mix.exs` parser SHALL tolerate common formatting variation (single vs. multi-line tuples, trailing commas, comments) without crashing, given `.ex` files are hand-formatted source code rather than machine-generated declarative data |
| NFR-006 | Version-semantics correctness | `~>` requirement satisfaction SHALL be verified against Hex's own documented pessimistic-operator semantics with dedicated unit tests covering both the 2-segment and 3-segment forms, not solely against `deps-bundler`'s existing `~>` test suite |

## 5. Data Model

No new persistent entities beyond what every ecosystem crate already models via the existing
`Dependency`/`ParseResult` traits.

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| Hex dependency (derived) | A `deps` list entry sourced from hex.pm | name (atom-derived string), version_requirement, only (dev/test scope, if present), is_git_or_path (bool) |
| Hex package (registry, cached) | Response from `GET /api/packages/{name}` | name, releases[] (version, inserted_at), licenses[], owners |
| Hex release detail (registry, cached) | Response from `GET /api/packages/{name}/releases/{version}` | version, retirement (nullable: reason, message), security_advisories[], requirements{} |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `mix.exs` with zero dependency tuples | No diagnostics returned (empty list) |
| `{:package, github: "..."}` / `git:` / `path:` tuple | Recognized and skipped — no diagnostic, no version check, no hover (FR-003) |
| Dependency tuple with `only: [:dev, :test]` | Parsed normally; requirement extraction unaffected by trailing keyword options (FR-004) — diagnostic-severity treatment for dev/test-only scope is an open question (see Open Questions #4) |
| Package name not found on hex.pm (404) | Diagnostic: "Unknown package: {name}", consistent with existing ecosystems' unknown-package handling |
| Resolved version has a non-null `retirement` field | Distinct retirement diagnostic with reason/message, separate from outdated diagnostic (FR-009) |
| `deps` function body is not a literal list (computed, conditional) | Logged at debug level, file returns empty diagnostics — no crash, no attempted evaluation (FR-014) |
| `mix.exs` is not syntactically well-formed Elixir | Parse error logged; handlers gracefully return empty results, consistent with how other ecosystems handle malformed manifests |
| hex.pm API unreachable or rate-limited | Cached data served if available; otherwise informational/loading state — no false "outdated" positive (NFR-003) |
| Umbrella project with multiple `apps/*/mix.exs` files | [NEEDS CLARIFICATION — see Open Questions #3] |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Manifest detection | `mix.exs` correctly routed to this ecosystem in test fixtures |
| SC-002 | Git/path exclusion | 100% of `github:`/`git:`/`path:`-sourced tuples excluded from registry resolution and diagnostics in fixture files |
| SC-003 | Hover coverage | Hover shows current requirement + latest version + license for all hex.pm-sourced dependencies with a resolvable requirement |
| SC-004 | Outdated diagnostic accuracy | 100% agreement between the outdated diagnostic count and the actual count of dependencies behind hex.pm's latest release, verified against fixture files |
| SC-005 | Retirement diagnostic accuracy | 100% of fixture dependencies with a non-null `retirement` field produce the distinct retirement diagnostic, not merely an outdated-version diagnostic |
| SC-006 | `~>` semantic correctness | Dedicated unit tests confirm Hex `~>` satisfaction matches Hex's documented semantics for both 2-segment and 3-segment requirement forms |
| SC-007 | Cross-ecosystem consistency | Hover/diagnostic/completion/code-action structure verified consistent with existing ecosystems, documented in `.local/testing/coverage.md` LSP Feature Matrix |

## 8. Agent Boundaries

### Always (without asking)
- Reuse the project's existing `HttpCache`-backed conditional-request caching pattern and `reqwest`/`rustls` HTTP stack — no new HTTP client library.
- Follow the existing `Ecosystem`/`Registry`/`ParseResult`/`Dependency`/`EcosystemFormatter` trait pattern established by existing ecosystem crates.
- Implement `generate_completions` directly, since the `Ecosystem` trait has no default for it.
- Write dedicated unit tests for `~>` requirement satisfaction rather than assuming `deps-bundler`'s test suite already covers Hex's semantics.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering any implementation complete.

### Ask First
- Whether `security_advisories[]` becomes its own diagnostic or is merged into the existing OSV-based vulnerability diagnostic pipeline (see Open Questions #2 and [[002-osv-vulnerability-diagnostics/spec]]).
- Whether to build a small purpose-built tokenizer for the tuple/keyword-list syntax vs. a tolerant regex/line-scan approach (see Open Questions #1) — this decision belongs to `/sdd plan`, not to ad hoc implementation choice.
- Umbrella-project (`apps/*/mix.exs`) support scope (see Open Questions #3).

### Never
- Attempt general-purpose Elixir expression evaluation to resolve a computed/conditional `deps` list.
- Fork or duplicate the project's shared HTTP-caching/registry-client conventions into a `deps-hex`-local reimplementation.
- Resolve `github:`/`git:`/`path:`-sourced dependency tuples against hex.pm.

## 9. Open Questions

- [NEEDS CLARIFICATION: Parsing strategy for the non-declarative `.ex` tuple syntax — regex/
  line-scan over the literal `{:name, "requirement", opts...}` pattern (fast, matches this
  project's generally tolerant parsing style) vs. a small purpose-built tokenizer over
  Elixir's tuple/keyword-list grammar (more robust against formatting variation, comments,
  and multi-line tuples). This is the single highest-impact open design question and should
  be resolved first in `/sdd plan`.]
- [NEEDS CLARIFICATION: Should `security_advisories[]` from the hex.pm releases endpoint be
  surfaced as its own new diagnostic, or deferred to/merged with the existing OSV-based
  vulnerability diagnostic (issue #124, [[002-osv-vulnerability-diagnostics/spec]])? hex.pm's
  own advisory data may be redundant with or complementary to OSV's Hex-ecosystem coverage —
  needs a comparison of the two data sources' coverage/freshness before deciding, and the
  non-empty-array shape of `security_advisories[]` itself still needs live verification
  against a known-vulnerable package.]
- [NEEDS CLARIFICATION: Umbrella project support — Elixir's umbrella-app layout places
  multiple `mix.exs` files under `apps/*/mix.exs` plus a root `mix.exs`, a project structure
  with no direct analogue among this project's 14 existing ecosystems (closest conceptual
  parallel is npm/Cargo workspaces, but the root `mix.exs` in an umbrella project typically
  has no `deps` of its own — it's a pure orchestrator). Is per-file (non-aggregated) handling
  sufficient for phase 1, treating each `apps/*/mix.exs` as an independent document like any
  other ecosystem's per-document model, or does the root/child relationship need explicit
  spec'd behavior?]
- [NEEDS CLARIFICATION: Should `only: :dev` / `only: [:dev, :test]` dependency-scope keyword
  options affect diagnostic severity — e.g. downgrading an outdated-version diagnostic's
  severity for a dev/test-only dependency the way this project may already treat dev-only
  dependencies in other ecosystems? A repo-wide check this session found no existing
  severity-differentiation-by-dev-scope precedent in `deps-cargo` or `deps-npm` (both of which
  already parse `[dev-dependencies]`/`devDependencies` sections but do not appear to alter
  diagnostic severity based on that classification) — if that reading is confirmed correct in
  `/sdd plan`, the most consistent choice is likely no special-casing for Hex either, but this
  should be explicitly confirmed against the actual severity-assignment code rather than
  assumed from this grep-level check.]
- [NEEDS CLARIFICATION: No project constitution exists at `specs/constitution.md` yet —
  cannot yet validate this spec against project-wide architectural principles beyond
  precedent-matching against existing ecosystem crates.]
- [NEEDS CLARIFICATION: No tracking issue filed yet for this spec — assign one, and confirm
  P4 priority still holds relative to backlog state at the time `/sdd plan` is picked up,
  consistent with how sibling new-ecosystem specs (e.g.
  [[044-precommit-hooks-ecosystem/spec|pre-commit hooks]]) flag priority as a suggestion
  rather than a mandate.]

## 10. See Also

- `crates/deps-bundler` — closest existing ecosystem by version-operator similarity (`~>`
  pessimistic operator), but its `~>` semantics must be independently verified against Hex's
  own documented behavior before reuse, not assumed identical (see FR-007, NFR-006, and
  Open Questions #1's sibling note in the Version Syntax section above).
- Issue #145 / [[004-release-freshness-signal/spec]] — hex.pm's per-release `inserted_at`
  timestamps (returned by `GET /api/packages/{name}`) are directly reusable by this feature's
  release-cooldown logic with no new timestamp-sourcing work.
- Issue #124 / [[002-osv-vulnerability-diagnostics/spec]] — potential interaction between
  hex.pm's own `security_advisories[]` field and this project's existing OSV.dev-based
  vulnerability diagnostic; see Open Questions #2.
- `filllabs/dependi#243` — closed/shipped competitor reference (the closest tracked VS Code
  extension competitor's own Elixir Hex support, shipped in v0.7.25 by direct user request).
- `.local/testing/playbooks/competitive-parity.md` — Known Gaps table where this candidate
  was first recorded (cycle 026, 2026-09-03) and re-confirmed unfiled across cycles 028, 029,
  and 036.
- `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` —
  consistency rule requiring identical behavior across all ecosystems.
- [Hex.pm API documentation](https://hex.pm/docs/api)
- [Hex version requirements documentation](https://hexdocs.pm/elixir/Version.html#module-requirements)
- [[MOC-specs]] — all specifications

---
aliases:
  - PyPI Private/Custom Index Support
  - pip --index-url / --extra-index-url Resolution
tags:
  - sdd
  - spec
  - research
  - enhancement
  - pypi
  - security
created: 2026-09-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[023-cargo-custom-registries/spec|Cargo Custom/Private Registry & Source-Replacement Resolution]]"
  - "[[032-npm-npmrc-registry-support/spec|npm .npmrc Custom/Private Registry Support]]"
---

# Feature: PyPI Private/Custom Index Resolution (`--index-url` / `--extra-index-url` / Poetry `source` / uv `index`)

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Issue**: none yet — file after this spec is reviewed
> **Branch**: (assign at implementation time, e.g. `feat/<issue>-pypi-private-index-support`)
> **Priority**: P3
> **Type**: research/enhancement (competitive parity gap)
> **Revision**: r3 (2026-09-02) — r2 corrected FR-005/FR-006/FR-007/FR-008/FR-013,
> NFR-003, SC-002/SC-004 and the Edge Cases table after a `rust-critic` design
> review of `plan.md` found the original FR-005 resolution order backwards
> (leaked private package names to `pypi.org`, inverted the dependency-confusion
> protection the spec claims — verified against pip's own docs, which the r1
> draft cited without checking) and the Poetry unlabeled-priority default
> backwards (verified against Poetry's own docs). r3 fixes 6 further defects a
> second critic pass found in r2's own fixes: the uv `default`/`explicit`
> mapping (verified against uv's own docs, also backwards in r2), an
> undocumented terminal-on-transport-error trade-off (FR-005(c)/NFR-003(3)), an
> undefined zero-hop chain case, and `AlternateRegistry.index`'s contract
> (now documented as an opaque routing key for chain sources, not always a
> literal URL). See `plan.md`'s Revision History for the full critic findings
> both revisions address.

## 1. Overview

### Problem Statement

`deps-pypi` has zero support for private/custom package index resolution —
confirmed live this session by reading the crate directly:

- `crates/deps-pypi/src/registry.rs:21,24` hardcodes
  `const PYPI_BASE: &str = "https://pypi.org/pypi";` and
  `const PYPI_SIMPLE_BASE: &str = "https://pypi.org/simple";` with no
  override mechanism of any kind — every lookup, regardless of any
  project configuration, goes to the public registry.
- `crates/deps-pypi/src/parser/requirements.rs:34-35` lists `--index-url`
  and `--extra-index-url` in `KNOWN_OPTIONS`, but purely so a
  `requirements.txt` line starting with either token is correctly
  classified as "a pip option line, not a dependency" during parsing
  (confirmed by reading the full option-line handling around lines 20-48).
  The URL value that follows the flag is never captured, stored, or used
  to resolve a single package.
- `crates/deps-pypi/src/parser/pyproject.rs` has no handling for Poetry's
  `[[tool.poetry.source]]` table (which declares additional/private
  package sources, e.g. `priority = "explicit"` for a company Artifactory
  feed) or uv's `[tool.uv.index]` / `[[tool.uv.sources]]` tables — grepped
  for `source`/`extra-index` this session; the only `source` occurrences
  in the file are an unrelated `PypiDependencySource` enum field (git/path
  provenance) and byte-span bookkeeping, confirmed by reading the matches.
- No `pip.conf`/`pip.ini` (pip's own config-file mechanism, analogous to
  npm's `.npmrc` or Cargo's `.cargo/config.toml`) or
  `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL` environment-variable handling
  exists anywhere in the crate.

This is the same silent-wrong-data bug class already fixed twice in this
project: issue #248 (Cargo) and the equivalent regression class closed by
[[032-npm-npmrc-registry-support/spec|032]] (US-004) for npm. Any
workspace using a self-hosted PyPI mirror (devpi, Artifactory, Azure
Artifacts, Nexus, a plain PEP 503 Simple HTML index behind a corporate
VPN) gets hover/diagnostic/completion data for the *wrong* index with no
indication anything is off — the LSP happily reports "up to date" or
"outdated" against `pypi.org` for a package that does not exist there at
all, or exists there with an unrelated version history.

`deps-cargo` (issues/PRs #431/#440/#441/#447) and `deps-npm`
(issue #502, PR #510, merged 2026-09-02) already ship a proven reference
pattern for exactly this class of problem, and the shared infrastructure
in `deps-core` is generic enough that `deps-pypi` needs no `deps-core`
change to reuse it:

- `DependencySource::AlternateRegistry { index, mirrors_crates_io }`
  (`crates/deps-core/src/parser.rs:894`) — a source-agnostic "resolved to
  a concrete, fetchable index URL" variant. `deps-pypi` would construct
  it directly (with `mirrors_crates_io: false`, the same choice npm made
  — no analogous mirror-verification concept exists for a PyPI-protocol
  index).
- `DependencySource::CustomRegistry { url }`
  (`crates/deps-core/src/parser.rs:882`) — the existing "present, but not
  resolved to a concrete, fetchable index" fail-closed state.
  `is_version_resolvable()` is already `false` for it
  (`crates/deps-core/src/parser.rs:920`), so every existing fail-closed
  gate (hover, diagnostics, code actions) applies with zero new code.
- `Registry::get_versions_from` / `get_latest_matching_from`
  (`crates/deps-core/src/registry.rs`) — defaulted trait methods any
  `Registry` impl can override; `deps-pypi`'s registry client would
  override these exactly as `CargoRegistry` and `NpmRegistry` do.
- `EcosystemFormatter::can_resolve_source` (added by #440's FR-016,
  defaulted to `DependencySource::is_version_resolvable()`) — the single
  override point gating hover/diagnostics/code-actions; `PypiFormatter`
  would override it exactly as `CargoFormatter`/`NpmFormatter` do.
- `deps_core::net_policy` (`HostClass`, `classify_host`,
  `RegistryAccessPolicy`, `WorkspaceRegistryAccess`) — the SSRF-hardening
  host classifier already gating Cargo's and npm's workspace-declared
  registries behind the shared `registries.workspace_registries` setting
  (`off` / `public_only` / `all`, default `public_only`, renamed from
  `cargo.workspace_registries` by [[032-npm-npmrc-registry-support/spec|032]]'s
  FR-008 precisely so later ecosystems would not need a parallel key).
  `deps-pypi` reuses this same setting.

What `deps-pypi` needs on top of that shared foundation is PyPI-specific:
parsing `requirements.txt` `--index-url`/`--extra-index-url` flag values
(currently discarded), Poetry's `[[tool.poetry.source]]` table, uv's
index-related tables, and — the one piece with no clean Cargo or npm
analogue — **`--extra-index-url`'s additive, multi-index semantics**: pip
checks *all* configured indexes for a match (first successful match wins
by default), unlike Cargo's replace-with (strictly one index per
dependency) or npm's scope-exclusive routing (one registry per `@scope`
prefix). See FR-005 and the Open Questions below for how this spec
proposes to narrow that ambiguity for phase 1 rather than fully solve
pip's real resolution-order semantics.

**Demand evidence** (verified live via `gh issue view` against
`filllabs/dependi`, this project's closest tracked competitor, per
`.local/testing/playbooks/competitive-parity.md`'s "Private/alternative
registry support" row): of the private/alternate-registry issues tracked
there as open against Dependi, three are PyPI-specific — the single
largest concentration for any one ecosystem in that list:

- `` github.com/filllabs/dependi/issues/285 `` — "Python / support
  private pypi simple html endpoint" (user wants PEP 503 Simple HTML
  index support for a private PyPI mirror — not even PEP 691 JSON, the
  plain HTML form).
- `` github.com/filllabs/dependi/issues/292 `` — "Add support for extra
  index servers" (user on Azure Artifacts private feed, needs BOTH
  `pypi.org` AND a private feed simultaneously — i.e. genuine
  `--extra-index-url` additive semantics, not a replace-only override).
- `` github.com/filllabs/dependi/issues/293 `` — "Unable to resolve Azure
  package feed" (same root cause as #292, filed independently as a bug by
  a different user — corroborating signal, not a single voice).

This is a stronger demand-concentration signal than the npm case that
justified issue #502/PR #510 (which had no comparable issue-count
concentration on Dependi's tracker for a single ecosystem).

`gh issue list --search "pypi private index"` and
`--search "extra-index-url"` against this repository (`bug-ops/deps-lsp`)
both returned zero hits this session — this is not a duplicate of an
existing open or closed issue.

> [!warning] Assumptions
> - Target indexes speak either the PEP 503 Simple HTML format or the
>   PEP 691 Simple JSON format `deps-pypi` already parses for the public
>   index (`PYPI_SIMPLE_BASE`/`SIMPLE_API_ACCEPT`,
>   `crates/deps-pypi/src/registry.rs:24,32`) — devpi, Artifactory PyPI
>   remote/virtual repos, Nexus, and Azure Artifacts feeds all implement
>   PEP 503 Simple HTML; PEP 691 JSON support is inconsistent among
>   self-hosted indexes. A private-index resolver must content-negotiate
>   the same way the public-index client already does (`Accept:
>   application/vnd.pypi.simple.v1+json` with a graceful fallback path),
>   **not** assume JSON-only — this is the PyPI-specific nuance flagged in
>   the finding and is load-bearing for FR-004.
> - `requirements.txt`/`constraints.txt` `--index-url`/`--extra-index-url`
>   flag values, Poetry's `[[tool.poetry.source]]` table, and uv's
>   `[tool.uv.index]` table are the three in-scope configuration surfaces
>   for phase 1 (see FR-001 through FR-003). `pip.conf`/`pip.ini` and
>   `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL` environment variables are a
>   fourth, real configuration surface pip itself supports but this spec
>   does **not** commit to implementing — see Open Questions.
> - **Divergent from both Cargo and npm's trust model, and unresolved by
>   this spec**: an index URL may legitimately embed HTTP basic-auth
>   userinfo (`https://user:pass@internal.example/simple`) per pip's own
>   documented convention, or rely on `keyring`/`.netrc` credential
>   resolution outside the URL entirely. Neither Cargo's nor npm's
>   phase-1 rule (reject any URL with embedded userinfo, parse no
>   auth-shaped key at all) has been re-validated against pip's specific
>   conventions here — see Out of Scope and Open Questions.

### Goal

A PyPI/pip dependency whose applicable index is overridden via
`requirements.txt` `--index-url`/`--extra-index-url`, Poetry's
`[[tool.poetry.source]]`, or uv's `[tool.uv.index]` gets the same
hover/diagnostic/completion value a `pypi.org` dependency gets today —
with zero regression for projects declaring no custom index, and with no
credential ever read, stored, or transmitted in this phase (auth wiring
deferred, see Out of Scope).

### Out of Scope

> [!danger] Explicit Exclusions
> - **All auth/credential handling** — HTTP basic-auth embedded in an
>   index URL (`https://user:pass@host/simple`), pip's `keyring` backend
>   integration, `.netrc` resolution, and any `PIP_INDEX_URL`-embedded
>   credential form. Phase 1 resolves *which* index a dependency belongs
>   to and fetches it unauthenticated; any URL with embedded userinfo
>   fails closed per FR-006/FR-011, matching the Cargo/npm precedent
>   exactly — it never reads, stores, or transmits a credential. `keyring`
>   and `.netrc` receive no detection or acknowledgment in phase 1. This
>   mirrors how [[032-npm-npmrc-registry-support/spec|032]] scoped npm's
>   `_authToken` family out of its own phase 1. A dedicated follow-up spec
>   is the right place to revisit pip's broader credential conventions.
> - **`pip.conf`/`pip.ini`** (pip's own INI-style config-file mechanism —
>   the closest PyPI analogue to `.npmrc`/`.cargo/config.toml`) and
>   **`PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL`-family environment
>   variables**. Both are real, commonly-used configuration surfaces (in
>   some CI/enterprise setups, the *primary* one — a `requirements.txt`
>   may declare no index flags at all and rely entirely on an ambient
>   `pip.conf`). Deliberately deferred to a separate follow-up spec: file
>   discovery precedence (per-project / per-user / per-site /
>   `PIP_CONFIG_FILE`) and env-var-vs-file precedence need to be
>   re-verified against current pip documentation before committing to an
>   implementation, which is out of this spec's scope. A workspace
>   relying solely on `pip.conf`/`PIP_*` env vars sees **no improvement**
>   from this spec's phase 1 — file the follow-up issue once this phase
>   ships.
> - **uv's `[tool.uv.sources]` non-index-routing variants** — uv's
>   `[tool.uv.sources]` table supports several key shapes; only the
>   `index = "<name>"` shape (routes a dependency to a named
>   `[tool.uv.index]` entry — registry routing, in scope per FR-013,
>   added 2026-09-02 after critic review found named uv indexes were
>   otherwise unreachable) is in scope. `git =`, `path =`, `workspace =
>   true`, and any other provenance-pinning shape are a distinct problem
>   (dependency provenance, not registry routing) and remain excluded — a
>   separate future spec, if one is ever filed, owns that surface.
> - **Package-name search/completion** for an index that does not
>   implement a PEP 503/691-compatible listing endpoint — same choice
>   [[032-npm-npmrc-registry-support/spec|032]]'s FR-011 made for npm:
>   unconditional no-op for alternate-index-resolved dependencies rather
>   than a per-index capability probe.
> - **A dedicated config-file watcher** — same choice Cargo's FR-013 and
>   npm's FR-016 made: document staleness (edits take effect on next
>   reparse of the affected manifest/requirements file) rather than build
>   a new watcher subsystem.
> - **Full pip index-priority/resolution-order semantics** — real pip
>   resolution across multiple `--extra-index-url` entries involves
>   version-matching across *all* configured indexes with configurable
>   tie-breaking (and, notoriously, a well-documented security footgun
>   where a malicious public package can shadow a same-named private one
>   — "dependency confusion"). This spec's FR-005 defines a deliberately
>   narrower phase-1 behavior and does not attempt to replicate pip's
>   full resolver; the dependency-confusion angle itself is flagged as a
>   Success Criterion (SC-004) rather than solved algorithmically in
>   phase 1.

## 2. User Stories

### US-001: `--index-url` full-mirror resolution in `requirements.txt`

AS A developer whose company routes all pip traffic through a corporate
mirror (Artifactory/devpi/Nexus)
I WANT dependencies in `requirements.txt` to resolve against that mirror
SO THAT hover/diagnostics reflect what my mirror actually serves (which
may lag or diverge from the public index)

**Acceptance criteria:**
```
GIVEN a requirements.txt starting with
      --index-url https://pypi.mycorp.example/simple/
WHEN I hover over any dependency declared later in the file
THEN the hover reflects pypi.mycorp.example's data, not pypi.org's, and
     no request is sent to pypi.org for that dependency
```

### US-002: `--extra-index-url` additive private-package resolution

AS A developer on an Azure Artifacts private feed who also needs public
PyPI packages in the same project
I WANT a dependency published only on my private feed to resolve there
SO THAT hover/diagnostics work for it without breaking public-package
resolution for everything else in the same file

**Acceptance criteria:**
```
GIVEN a requirements.txt containing
      --extra-index-url https://pkgs.dev.azure.com/myorg/_packaging/myfeed/pypi/simple/
  AND a dependency name that exists only on that private feed
WHEN I hover over that dependency
THEN the hover shows data resolved from the extra index, not "package
     not found" against pypi.org alone
```

### US-003: Poetry `[[tool.poetry.source]]` resolution

AS A developer using Poetry with a declared private source
I WANT dependencies routed to that source (per Poetry's `priority`
semantics) to resolve against it
SO THAT hover/diagnostics reflect the correct index for a
`pyproject.toml`-based project, not only `requirements.txt`

**Acceptance criteria:**
```
GIVEN a pyproject.toml with
      [[tool.poetry.source]]
      name = "internal"
      url = "https://pypi.mycorp.example/simple/"
      priority = "explicit"
  AND a dependency declared with source = "internal"
WHEN I hover over that dependency
THEN the hover reflects pypi.mycorp.example's data
```

### US-004: No regression for public-only projects

AS A developer with no index override anywhere in my project
I WANT the LSP to keep behaving exactly as it does today
SO THAT this feature introduces zero risk for the overwhelming majority
of PyPI/pip projects

**Acceptance criteria:**
```
GIVEN no --index-url/--extra-index-url flag, no [[tool.poetry.source]],
      and no [tool.uv.index] table anywhere in the project
WHEN I hover over any dependency
THEN the hover is byte-identical to pre-feature behavior (pypi.org)
```

### US-005: Unresolved/misconfigured index fails closed

AS A developer whose `--index-url` or `[[tool.poetry.source]]` entry
points at an unreachable, invalid, or policy-blocked URL
I WANT the LSP to show no data for dependencies routed to it rather than
silently checking the public index
SO THAT I never mistake a stale/wrong public-index result for my private
index's actual state — and, symmetrically, so a malicious or
typo-squatted public package cannot silently supersede a private package
of the same name (the dependency-confusion risk noted in Out of Scope)

**Acceptance criteria:**
```
GIVEN --index-url not-a-valid-url in requirements.txt
WHEN I hover over any dependency in that file
THEN no version data is shown, and no request is sent to pypi.org for
     that dependency (mirrors the regression class issue #248 fixed for
     Cargo and the equivalent class 032 closed for npm)
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL parse `--index-url <url>` and `--extra-index-url <url>` option lines in `requirements.txt`/`constraints.txt` (both `--flag value` and `--flag=value` spellings, matching the existing `KNOWN_OPTIONS` token-recognition grammar in `crates/deps-pypi/src/parser/requirements.rs`) and capture the URL value, instead of discarding it as today | must |
| FR-002 | WHEN an `--index-url` value is present and passes URL validation (see FR-006) THE SYSTEM SHALL treat it as the replacement default index for every dependency in that file that has no more specific override — analogous to npm's top-level `registry=` (032 FR-003) and Cargo's `[source]` replace-with | must |
| FR-003 | WHEN one or more `--extra-index-url` values are present and pass URL validation THE SYSTEM SHALL treat each as an additional index to be checked for dependencies not found (or not yet resolved) via the primary index — see FR-005 for the phase-1 resolution-order rule that narrows pip's full multi-index semantics | must |
| FR-004 | THE SYSTEM SHALL content-negotiate against a resolved alternate index the same way `deps-pypi` already does for the public Simple API — requesting `SIMPLE_API_ACCEPT` (`application/vnd.pypi.simple.v1+json`, PEP 691) and falling back to parsing the PEP 503 Simple HTML response when the alternate index does not honor the `Accept` header or returns `text/html` — because self-hosted indexes (devpi, Artifactory, Azure Artifacts) do not reliably serve PEP 691 JSON, unlike `pypi.org` | must |
| FR-005 | Resolution order depends on whether `--index-url` is **explicit** in the file. **(a) Explicit primary**: WHEN a dependency name is present on both the explicit `--index-url` index and one or more `--extra-index-url` indexes THE SYSTEM SHALL resolve it against the explicit primary first, only falling through to `--extra-index-url` indexes (declaration order) if the package is absent there — an explicit `--index-url` is a deliberate, user-stated choice to check that index first, so this direction carries no name-disclosure risk. **(b) No explicit primary**: WHEN a file has one or more `--extra-index-url` values but no explicit `--index-url` THE SYSTEM SHALL check the declared extras (declaration order) **before** the implicit public `pypi.org` fallback — never the reverse. Rule (b) exists specifically so a private-only package name (US-002) is never sent to `pypi.org` before the user's own declared index has had a chance, and so a same-named public package can never silently shadow a private one the user explicitly configured. This is the sole phase-1 resolution-order rule — no configuration escape hatch; revisit only if a concrete workspace need for a different order surfaces after shipping. **Corrected 2026-09-02** (critic review, verified against pip's own docs — see NFR-003): pip itself documents no precedence between `--index-url`/`--extra-index-url` ("there is no priority in the locations that are searched... the best match... is selected") and explicitly warns `--extra-index-url` is unsafe for private packages precisely because of this merge-and-pick-best behavior. This spec deliberately does **not** replicate that unsafe pip default — rule (b) is a phase-1 safety choice, not a claim of pip-behavior parity. **(c) Transport failure on any hop other than the last is terminal, not skipped** (confirmed 2026-09-02, second critic pass): a connection error, timeout, or 5xx from a hop THE SYSTEM SHALL propagate immediately as the chain's result rather than falling through to the next hop — including case (b)'s declared extras. This means an unreachable declared extra (e.g. a developer off the corporate VPN) halts resolution for *every* dependency in that file, including ordinary public ones, rather than silently falling through to `pypi.org` — a deliberate, confirmed trade-off: falling through on transport failure would send every affected package's name to `pypi.org` whenever the private index is merely unreachable, which is the exact disclosure NFR-003(2) exists to prevent. `PackageNotFound` (an explicit 404, or a 200 response with an empty listing) is the only condition that continues to the next hop — see NFR-003(3) for the required distinguishable diagnostic this produces | must — the narrowed rule itself, not a promise of full pip-resolver parity |
| FR-006 | WHEN an explicit `--index-url`/`[[tool.poetry.source]]` (`primary`/`default` priority)/`[tool.uv.index]` (`default = true`) URL value is present but fails validation (non-https, contains userinfo, or is not well-formed) or is blocked by FR-008's policy THE SYSTEM SHALL represent the affected dependency's source as `DependencySource::CustomRegistry { url: <the raw value as written> }` — the existing `deps-core` variant whose `is_version_resolvable()` is already `false` — logging a `tracing::warn!` naming the raw value, and SHALL NOT fetch that dependency's name against `pypi.org`. WHEN an `--extra-index-url`/supplemental-priority-source value fails the same validation THE SYSTEM SHALL log the same warning but SHALL drop only that entry from the fallback chain (per FR-005) rather than failing the whole dependency closed — an extra is additive/optional by definition, so one misconfigured extra must not block resolution via the primary or the remaining valid extras/implicit public fallback. Userinfo rejection follows the Cargo/npm precedent exactly — resolved, not deferred: pip's URL-embedded-credential and `keyring`/`.netrc` conventions are out of scope for phase 1 (see Out of Scope), so the fail-closed-per-entry rule applies uniformly regardless of pip-specific auth mechanisms | must |
| FR-007 | THE SYSTEM SHALL parse Poetry's `[[tool.poetry.source]]` table entries (`name`, `url`, and `priority` keys) in `pyproject.toml`, and SHALL resolve a dependency declaring `source = "<name>"` against the matching entry's `url`, subject to the same FR-006 validation and FR-008 policy gate. An entry with no explicit `priority` key SHALL be treated as `priority = "primary"` — this matches current Poetry documentation ("Sources without a priority are considered primary sources, too"), verified live 2026-09-02 (see plan.md for the citation; the original phase-1 draft of this spec had this backwards as `supplemental` and has been corrected). **When at least one `primary`/`default`-priority source is configured, no implicit `pypi.org` hop is appended** — also verified live against current Poetry documentation ("If you configure at least one primary source, the implicit PyPI source is disabled"), added 2026-09-02 after a second critic pass found the original citation incomplete: without this second sentence, FR-005(a)'s "no implicit public hop for an explicit primary" rule reads unmotivated for Poetry specifically and could be mis-"fixed" later into appending one, breaking Poetry parity | must |
| FR-008 | THE SYSTEM SHALL classify every **explicitly-declared** resolved index URL's host (an explicit `--index-url`, every `--extra-index-url`, every Poetry/uv source) through `deps_core::net_policy::classify_host` and gate the fetch behind the existing shared `registries.workspace_registries` setting (`off` / `public_only` / `all`, default `public_only`) — the same setting Cargo and npm already gate on, reused as-is with no new `pypi.*` key, consistent with why 032's FR-008 renamed it away from a Cargo-specific name in the first place. The **implicit public `pypi.org` fallback** used by FR-005(b) is never subject to this gate — it is the same ungated public-tier client `deps-pypi` already uses for every plain dependency today, so `workspace_registries = off` blocks only the explicitly-declared extras/primary, never ordinary public-package resolution in the same file (this is the fix for a defect the critic review found in the original phase-1 draft: routing every dependency in an extras-carrying file through the gated chain would have made `off` incorrectly break plain public packages too) | must |
| FR-009 | THE SYSTEM SHALL add `PypiFormatter::can_resolve_source` (overriding the existing defaulted `EcosystemFormatter::can_resolve_source` hook) so hover/diagnostics/code-actions correctly gate on a resolved `AlternateRegistry` source — no `deps-core` trait change required | must |
| FR-010 | THE SYSTEM SHALL add `Registry::get_versions_from` / `get_latest_matching_from` overrides on `deps-pypi`'s registry client, routing fetches for `AlternateRegistry`-sourced dependencies to the resolved index instead of `PYPI_BASE`/`PYPI_SIMPLE_BASE` — reuses the existing defaulted `deps-core::Registry` trait methods. WHEN a resolved `AlternateRegistry`'s `index` has no registered client THE SYSTEM SHALL return `PackageNotFound` and SHALL NOT fall back to `pypi.org` — the same fail-closed rule 032's FR-010 established for npm, closing the same #248 regression class | must |
| FR-011 | THE SYSTEM SHALL NOT read, log, or transmit any embedded URL userinfo (`user:pass@`) or any other credential-shaped value from an index URL — parsing SHALL reject (per FR-006) rather than strip-and-proceed, so no code path ever holds a credential value in memory. **Implementation requirement (added 2026-09-02, implementation-review round — the first implementation attempt violated this exact rule by logging and retaining the raw, full URL including userinfo)**: when FR-006's `tracing::warn!` names the rejected entry and when `CustomRegistry { url }` retains it for the document's lifetime, THE SYSTEM SHALL use a **redacted** form of the raw value (userinfo replaced with a fixed marker, e.g. `https://***@host/path`, not the literal `user:pass`) — never the unredacted raw string. This still lets a user identify *which* declared index was rejected without ever holding or displaying the credential itself. `keyring`/`.netrc` mechanisms receive no acknowledgment or detection in phase 1 — entirely out of scope, deferred to a dedicated auth-handling follow-up spec (see Out of Scope) | must — security-blocking |
| FR-012 | THE SYSTEM SHALL document `requirements.txt`/`pyproject.toml` index-declaration staleness as a known limitation (edits take effect on next reparse of the affected file) rather than add a dedicated file watcher, mirroring Cargo's FR-013 and npm's FR-016 resolution | must — the choice itself, not a specific mechanism, is mandatory |
| FR-013 | uv's `[tool.uv.index]` table entries (`name`, `url`, `default`, `explicit` keys) SHALL be parsed and resolved using the same FR-006/FR-008 validation and policy gate as Poetry sources and `requirements.txt` flags, mapped per uv's own documented semantics (verified live 2026-09-02 against `docs.astral.sh/uv/concepts/indexes/`, **corrected from an initial draft that had this backwards**): every entry that has neither `default = true` nor `explicit = true` is searched automatically for every dependency (a chain hop, in declaration order — the uv analogue of `--extra-index-url`, not a named-only source); the entry with `default = true` (uv permits at most one) is uv's lowest-priority, last-resort index — checked *after* every non-`explicit` entry, replacing the implicit `pypi.org` fallback in that final slot rather than acting as a checked-first primary; an entry with `explicit = true` is parsed into named sources only, never auto-included in the chain. In addition (added 2026-09-02, critic review — an `explicit` uv index was otherwise undeliverable), a `[tool.uv.sources]` entry of the form `<name> = { index = "<index-name>" }` SHALL be parsed and SHALL resolve that dependency against the matching `[tool.uv.index]` entry's URL (works for both `explicit` and non-`explicit` entries), the direct uv analogue of Poetry's FR-007 `source = "<name>"`. Every other `[tool.uv.sources]` shape (`git =`, `path =`, `workspace = true`, or any combination without an `index =` key — dependency provenance, not registry routing) remains explicitly out of scope | should |
| FR-014 | Package-name search/completion for a dependency resolved to an alternate index SHALL no-op rather than error or query `pypi.org`, mirroring 032's FR-011 for npm | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No credential-shaped value (URL userinfo, or any future `keyring`/`.netrc`-adjacent field) is ever parsed, held in memory, logged, or transmitted in phase 1 — verified by a structural test asserting the parsed config type has no field capable of holding such a value, matching the pattern Cargo's NFR-001 and npm's NFR-001 established |
| NFR-002 | Security | Every resolved index URL is validated (https-only, no userinfo, with the same test-only loopback carve-out precedent as Cargo/npm) and normalized (trailing slash handling consistent with PEP 503's `/simple/{name}/` path convention) before any network request |
| NFR-003 | Security | Three residual risks/costs, all must be stated for security-reviewer sign-off before implementation merges. **(1) Inbound reachability**: an unauthenticated HTTPS GET to a workspace-declared index still occurs, which is reachability into the user's internal network usable for existence probing by a hostile repository — mitigated identically to Cargo/npm by `registries.workspace_registries` defaulting to `public_only`. **(2) Outbound name disclosure** (added 2026-09-02, critic review — absent from the original phase-1 draft): resolving a dependency in a file with only `--extra-index-url` declared (no explicit primary) inherently requires querying *some* index for that package name; FR-005(b) mandates the declared extras are queried before the implicit `pypi.org` fallback specifically so a private package's name is never sent to the public index first, and so a same-named public package can never silently win over an explicitly-configured private one — this is the corrected, safer direction (the original draft had this backwards; verified against pip's own documentation, which explicitly warns `--extra-index-url` is unsafe for private packages for exactly this reason). Sign-off should confirm rule (b)'s ordering, not just its existence. **(3) Availability cost of (2)'s mitigation** (added 2026-09-02, second critic pass): FR-005(c)'s terminal-on-transport-failure rule, which (2) requires, means an unreachable declared extra blocks resolution for every dependency in that file — including ordinary public ones that have nothing to do with the private index — rather than degrading gracefully to `pypi.org`. THE SYSTEM SHALL surface a distinguishable diagnostic for this case **visible to the user through the LSP's normal hover/diagnostic surface** — not merely a `tracing::warn!` log line, which a user running without `RUST_LOG=debug` never sees (fixed 2026-09-02, implementation-review round: the first implementation attempt logged this correctly but never routed it to hover/diagnostics, so every affected dependency showed the same generic "registry lookup failed" message as any other network error, defeating the purpose of distinguishing this case at all). Wording along the lines of "extra index unreachable — resolution halted rather than falling back to pypi.org" so a developer working off-VPN can tell this apart from a genuinely broken/nonexistent package. Sign-off should confirm this availability/confidentiality trade-off is accepted, not merely that it exists |
| NFR-004 | Performance | No additional filesystem/network activity for a project declaring no index override anywhere (`requirements.txt`, `pyproject.toml` Poetry/uv tables) — zero regression path, verified by existing test suite |
| NFR-005 | Reliability | Zero behavior change for any project declaring no custom index — verified by the existing `deps-pypi` test suite producing unchanged results |
| NFR-006 | Maintainability | Both FR-005 orderings are verified by tests: (a) a package present on both an explicit primary and an extra resolves to the primary's data; (b) with no explicit primary, a package present on both a declared extra and `pypi.org` resolves to the extra's data and issues no `pypi.org` request for that name; (c) a package present only on an extra index resolves there without a "not found" false negative in either case |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencySource::AlternateRegistry` | Existing `deps-core` variant, reused as-is — the FR-002/FR-003/FR-007 resolved state | `index: String`, `mirrors_crates_io: bool` (always `false` for PyPI, matching npm's choice). **Note (added 2026-09-02, second critic pass)**: `deps-core`'s doc comment describes `index` as "the resolved index URL" — accurate for Cargo/npm, which always store a literal URL there. PyPI's multi-hop chain sources (FR-005) instead store an **opaque, parser-owned routing key** (not a URL — see plan.md §3's `ResolvedChain::key`) for any dependency whose source is a chain rather than a single index; a single-hop named-source dependency (Poetry/uv `source`/`index =`) still stores that source's literal URL, matching Cargo/npm's convention. No `deps-core` consumer renders or parses this field as a URL today, so this is a documentation-level widening of the field's existing contract, not a type change — permitted by this spec's "Never widen the `deps-core` trait surface" boundary, which does not cover doc comments |
| `DependencySource::CustomRegistry` | Existing `deps-core` variant, reused as PyPI's FR-006 fail-closed state — no new variant introduced | `url: String` — the raw value as written; `is_version_resolvable()` already `false` |
| `PypiIndexConfig` | New `deps-pypi` type — resolved index configuration for one manifest/requirements file | `primary: Option<Result<PypiIndexUrl, InvalidEntry>>` (from `--index-url` or a `priority = "primary"`/`"default"`-equivalent Poetry source), `extras: Vec<Result<PypiIndexUrl, InvalidEntry>>` (declaration order preserved, FR-005), `named_sources: HashMap<String, Result<PypiIndexUrl, InvalidEntry>>` (Poetry `[[tool.poetry.source]]` keyed by `name`, consulted when a dependency declares `source = "<name>"`) |
| `InvalidEntry` | New `deps-pypi` type — a present-but-unusable entry, carrying what FR-006 needs to build `CustomRegistry` and to warn | `raw: String` (as written), `reason` (validation failure kind) |
| `PypiIndexUrl` | Validated, normalized index URL newtype, new and `deps-pypi`-local (mirrors `NpmRegistryIndex` from 032 rather than promoting a shared type — see Open Questions on whether a third near-identical newtype across Cargo/npm/PyPI is worth consolidating into `deps-core`) | https-only, no userinfo, PEP 503-path-normalized |
| `PypiRegistry` | Existing `deps-pypi` `Registry` impl, extended into a router mirroring `NpmRegistry`'s `alternates` map | `+ alternates: Arc<DashMap<String, Arc<PypiRegistry>>>` (root-owned only, keyed by chain identity — see plan.md's C2 fix, not by primary URL alone), `+ fallback_chain: Vec<Arc<PypiRegistry>>` (resolved clients, not raw URLs — see plan.md's C1 fix), `+ simple_base: String` (distinct from the existing `index_url` field, which is the package-*search* index only — see plan.md's C4 fix; version-fetch URLs are built from `simple_base`) |
| `Registry::get_versions_from` / `get_latest_matching_from` | Existing defaulted `deps-core::Registry` trait methods | Overridden by `PypiRegistry`, no signature change |
| `EcosystemFormatter::can_resolve_source` | Existing defaulted `deps-core` trait method | Overridden by `PypiFormatter`, no signature change |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| No `--index-url`/`--extra-index-url`/Poetry source/uv index anywhere | Byte-identical to today's behavior (US-004) |
| `--index-url` present (explicit primary), no dependencies reference anything special | Every dependency in the file routes to the new primary index first, then declared extras (FR-002, FR-005a) |
| Only `--extra-index-url` present, no `--index-url` | Every dependency routes through the declared extras first, implicit public `pypi.org` last (FR-005b) — **not** the reverse |
| Explicit `--index-url` present, dependency exists on both primary and extra | Primary index's data wins (FR-005a, NFR-006) |
| Only `--extra-index-url` present, dependency exists on both an extra and `pypi.org` | The extra's data wins — `pypi.org` is never queried for that name until every declared extra misses (FR-005b, NFR-003) |
| `--extra-index-url` present, dependency exists only on the extra index | Resolved via the extra index, not reported "not found" (US-002, FR-005) |
| Explicit `--index-url not-a-valid-url` | Source becomes `CustomRegistry { url: "not-a-valid-url" }`; warn logged; no `pypi.org` fallback (FR-006, US-005) |
| An `--extra-index-url` entry fails validation, primary or other extras are still valid | That one entry is dropped from the chain (warn logged); resolution proceeds via the primary/remaining valid extras/implicit public fallback — does **not** fail the whole dependency closed (FR-006, corrected 2026-09-02) |
| Index URL contains embedded userinfo (`https://user:pass@host/simple/`) | Rejected per FR-006/FR-011 → fails closed per the entry-specific rule above (Cargo/npm precedent, resolved for phase 1) |
| `[[tool.poetry.source]]` entry with no `priority` key | Treated as `priority = "primary"` (FR-007, corrected 2026-09-02 — matches current Poetry docs) |
| `[[tool.poetry.source]]` entry with no matching `source = "<name>"` on any dependency | Parsed but never consulted — no effect |
| `pyproject.toml` dependency declares `source = "<name>"` with no matching `[[tool.poetry.source]]` entry | Treated as unresolvable per FR-006 (name looked up, not found in `named_sources`) rather than silently falling back to `pypi.org` |
| Alternate index returns PEP 503 HTML instead of PEP 691 JSON | Parsed via the existing HTML-fallback path (FR-004) — not treated as an error |
| Alternate index unreachable / times out | No version data shown; no panic; identical shape to public-index-unreachable handling today; a timeout/5xx does **not** trigger fallthrough to the next chain entry the way `PackageNotFound` does (see plan.md's failure-taxonomy fix) |
| `requirements.txt` `--index-url`/`--extra-index-url` edited after initial resolution | Stale until the affected file is next reparsed (FR-012, documented limitation) |
| `workspace_registries = off`, file has an **explicit valid `--index-url`** plus a blocked `--extra-index-url` | The extra drops out of the chain (FR-006); the chain still has a working hop (the explicit primary), so every dependency resolves via it exactly as under `public_only`/`all` (FR-008) — corrected 2026-09-02 (this is the S6 fix: a blocked extra never breaks a chain that still has a valid hop) |
| `workspace_registries = off`, file declares **only** `--extra-index-url` entries (no explicit primary), every extra blocked | Every extra drops out (FR-006); with no explicit primary, the resulting chain has zero hops. THE SYSTEM SHALL resolve every plain dependency in that file as plain `DependencySource::Registry` (byte-identical to a file with no declarations at all) — **not** per-dependency fail-closed and **not** an undefined/empty `AlternateRegistry` chain (fixed 2026-09-02, second critic pass — this case was previously undefined; there is no per-package distinction at parse time, so every plain dependency in an extras-only file necessarily shares this outcome) |
| A declared `--extra-index-url` is unreachable (connection error/timeout) with no explicit primary in the file (FR-005(b)/(c)) | Resolution halts for every dependency in that file, including ordinary public ones — a distinguishable diagnostic is shown (NFR-003(3)), not a silent/generic failure. Confirmed 2026-09-02 as an intentional availability/confidentiality trade-off, not a defect |
| Chain resolution reaching the "supplemental"/extras stop condition | Stops at the first hop with *any* non-empty version list — an approximation of Poetry's own "yields a compatible package **distribution**" (version-aware) condition, not a full re-implementation of it. Stated explicitly (added 2026-09-02, second critic pass) as a phase-1 divergence, consistent with this spec's existing disclaimer that it does not replicate pip's/Poetry's full resolver |
| An index URL resolves to an RFC1918/loopback host under the default `public_only` policy | Blocked by FR-008's policy → that entry drops from the chain (extras) or fails closed (explicit primary); permitted only under `all` |
| Same package name present with different indexes on two separate requirement lines (rare but possible via multiple `-r` includes) | Out of scope for phase 1's per-file resolution model — documented limitation, not silently merged |
| `-r base.txt` include declares `--index-url`, the includer file's own dependencies do not | Config does not propagate along the include graph in phase 1 — the includer's dependencies resolve against `pypi.org` unless it declares its own override. Documented known limitation (decided 2026-09-02), not implemented in phase 1 |
| `pip.conf`/`PIP_INDEX_URL` present, no in-file `--index-url` | No effect in phase 1 (Out of Scope) — dependencies resolve exactly as they do today, against `pypi.org`, which is a known false-negative for that class of project |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Private-index dependency (via `--index-url`) shows live hover/diagnostic/completion data | Pass on a real or mocked devpi/Artifactory-shaped PEP 503 fixture |
| SC-002 | `--extra-index-url`-only dependency (absent from the public/primary index) resolves correctly | Pass on a fixture mirroring US-002/Dependi issue #292's Azure Artifacts scenario. **Caveat (added 2026-09-02)**: this verifies phase 1's unauthenticated resolution logic against a fixture that returns 200; the real Dependi #292/#293 Azure Artifacts feed requires authentication (401/403 unauthenticated) and is therefore only reachable once the deferred auth follow-up spec ships — SC-002 proves the routing/fallback mechanism works, not that the live Azure scenario is solved end-to-end in phase 1 |
| SC-003 | Zero regression on projects declaring no index override | Every existing `deps-pypi` test produces unchanged results |
| SC-004 | Misconfigured/unreachable extra never silently falls back to `pypi.org` ahead of a valid remaining index, and — the corrected direction (2026-09-02) — a private/extra-index match is never silently shadowed by a same-named `pypi.org` result when no explicit primary is declared | Test mirroring the #248/032 regression pattern, adapted for PyPI's FR-005(a)/(b) order: (a) explicit-primary-then-extras for files with `--index-url`; (b) extras-then-implicit-public for files without it. Asserts no `pypi.org` request occurs before the declared extras are exhausted in case (b), and that a `CustomRegistry`-sourced dependency never triggers a `pypi.org` request at all |
| SC-005 | No credential-shaped value is ever parsed into memory | Structural test per NFR-001/FR-011 |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features` before considering a task complete.
- Follow the Registry Integration Gate (`.claude/rules/continuous-improvement.md`) — verify against a real or mocked private PyPI-protocol index before filing the implementation PR.
- Update `CHANGELOG.md`, `ECOSYSTEM_GUIDE.md`, `.local/testing/coverage.md` (PyPI row), `.local/testing/playbooks/pypi.md` (create if absent), `.local/testing/regressions.md`.
- Reuse `DependencySource::AlternateRegistry`/`CustomRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `EcosystemFormatter::can_resolve_source`, and `deps_core::net_policy` as-is rather than adding parallel `deps-pypi`-only mechanisms.

### Ask First
- Any decision that touches auth/credential handling (URL userinfo, `keyring`, `.netrc`) — explicitly out of scope for this spec; a dedicated follow-up spec owns pip's broader credential conventions.
- Implementing `pip.conf`/`PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL` support — explicitly out of scope, deferred to a separate follow-up spec; do not add ad hoc env-var reading in this feature.
- Consolidating `PypiIndexUrl` with Cargo's `RegistryIndex`/npm's `NpmRegistryIndex` into a shared `deps-core` type — a cross-crate refactor beyond this spec's own file scope, deferred until a third near-identical implementation makes the duplication concrete, not decided here.
- Any change to FR-005's phase-1 resolution-order rule (primary-then-extras) — this is a deliberate narrowing of pip's real resolver behavior, decided as the sole phase-1 rule with no configuration escape hatch; any deviation needs explicit sign-off given the dependency-confusion security angle (NFR-003).

### Never
- Parse, log, or transmit any credential-shaped value (URL userinfo or otherwise) in this phase (FR-011).
- Fall back to `pypi.org` when an explicit `--index-url`/`--extra-index-url`/Poetry-source/uv-index override is present but fails to resolve (FR-006) — the exact bug class issue #248 fixed for Cargo and 032 fixed for npm.
- Widen the `deps-core` `Registry`/`EcosystemFormatter` **trait** surface — every hook this spec needs already exists generically from the Cargo/npm work.

## 9. Open Questions

All blocking `[NEEDS CLARIFICATION]` items are resolved as of 2026-09-02:

- **Auth/credential handling**: resolved — reject any index URL with embedded
  userinfo, matching the Cargo/npm precedent exactly (FR-006/FR-011). No
  `.netrc` detection or acknowledgment in phase 1; pip's broader credential
  conventions (`keyring`, `.netrc`, URL-embedded basic-auth) are entirely out
  of scope, owned by a dedicated future auth-handling spec.
- **`pip.conf`/`pip.ini` and `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL`**:
  resolved — out of scope for this spec, deferred to a separate follow-up
  spec/issue filed after this phase ships. File-discovery precedence needs
  its own research pass rather than blocking this feature.
- **uv schema scope**: resolved — FR-013 covers `[tool.uv.index]` table
  entries (`name`, `url`, `default`) plus `[tool.uv.sources]`'s
  `index = "<name>"` shape (added 2026-09-02, critic review: a named uv
  index was otherwise unreachable). Every other `[tool.uv.sources]` shape
  (`git =`, `path =`, `workspace = true`) is excluded outright — dependency
  provenance, not registry routing, and a distinct problem from this spec's
  scope.
- **FR-005 resolution order**: resolved, and **corrected 2026-09-02** after
  critic review found the original rule backwards. Two sub-rules: (a) an
  explicit `--index-url` is checked before its file's extras (safe — a
  deliberate user choice); (b) with no explicit primary, declared extras are
  checked *before* the implicit `pypi.org` fallback (not after) — verified
  against pip's own documentation, which states there is no precedence
  between `--index-url`/`--extra-index-url` and explicitly warns
  `--extra-index-url` is unsafe for private packages for exactly the reason
  rule (b) avoids. No configuration escape hatch in either sub-rule.

Non-blocking, deliberately deferred:

- Whether `PypiIndexUrl` should eventually be consolidated with Cargo's
  `RegistryIndex`/npm's `NpmRegistryIndex` into one `deps-core`-shared
  newtype is left for a later refactor once three near-identical
  implementations exist and the actual duplication is visible, rather than
  speculatively generalizing now (matches this project's stated MVP/
  no-premature-abstraction principle).

## 10. See Also

- [[constitution]] — project principles (not yet created for this project; cross-check against `.claude/rules/*.md` instead)
- [[MOC-specs]] — all specifications
- [[023-cargo-custom-registries/spec|023-cargo-custom-registries]] — the original reference implementation pattern: `DependencySource::AlternateRegistry`, `Registry::get_versions_from`/`get_latest_matching_from`, `EcosystemFormatter::can_resolve_source`, `deps_core::net_policy` host-classifier gating
- [[032-npm-npmrc-registry-support/spec|032-npm-npmrc-registry-support]] — closest analogue: the most recently shipped instance of this pattern, and the source of the shared `registries.workspace_registries` policy key this spec reuses as-is
- `.local/testing/playbooks/competitive-parity.md` — "Private/alternative registry support" row naming PyPI, Maven, NuGet, Go, Composer, and Bundler as unfiled follow-ons to the Cargo pattern
- Dependi private-registry demand evidence (different repository, links intentionally not auto-linked): `` github.com/filllabs/dependi/issues/285 ``, `` github.com/filllabs/dependi/issues/292 ``, `` github.com/filllabs/dependi/issues/293 ``
- `crates/deps-core/src/parser.rs` — `DependencySource`, `AlternateRegistry`, `CustomRegistry`, `is_version_resolvable`
- `crates/deps-core/src/registry.rs` — `Registry` trait, `get_versions_from`/`get_latest_matching_from`
- `crates/deps-core/src/net_policy.rs` — `HostClass`, `classify_host`, `RegistryAccessPolicy`, `WorkspaceRegistryAccess`
- `crates/deps-pypi/src/registry.rs` — `PYPI_BASE`, `PYPI_SIMPLE_BASE`, `SIMPLE_API_ACCEPT`, the hardcoded constants and content-negotiation pattern this spec extends
- `crates/deps-pypi/src/parser/requirements.rs` — `KNOWN_OPTIONS`, the existing `--index-url`/`--extra-index-url` token recognition this spec extends to actually capture the URL value
- `crates/deps-pypi/src/parser/pyproject.rs` — existing PEP 621/Poetry dependency parsing this spec builds `[[tool.poetry.source]]` resolution on top of
- Issue #248 — the Cargo silent-fallback-to-public-registry bug this spec's FR-006/US-005 explicitly avoid repeating for PyPI

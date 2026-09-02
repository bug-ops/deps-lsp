---
aliases:
  - Cargo Custom Registries
  - Cargo Private Registry Resolution
tags:
  - sdd
  - spec
  - enhancement
  - security
  - cargo
created: 2026-09-01
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[024-net-policy-dns-rebinding/spec|DNS Rebinding Bypass of net_policy]]"
---

# Feature: Cargo Custom/Private Registry & Source-Replacement Resolution

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Branch**: feat/431-cargo-custom-registries
> **Status**: Shipped — PR 1a #440 (registries, issue #431), PR 1b #447 (source replace-with + NFR-003 SSRF sign-off, issue #443)
> **Priority**: P4
> **Type**: enhancement

## 1. Overview

### Problem Statement

`deps-cargo` correctly *parses* `git`/`path`/`registry`/`registry-index`
dependency sources — `DependencySource::CustomRegistry { url }` already
captures a `registry = "my-corp"` alias, and `[source]` replace-with tables
are read into the parse result — but version *resolution* is skipped for
every source except the default crates.io registry. Verified against live
code:

- `DependencySource::is_version_resolvable()` (`crates/deps-core/src/
  parser.rs:900`) only matches `Registry`, so hover, diagnostics
  (`generate_diagnostics_from_cache`), and code actions all gate a
  `CustomRegistry` dependency out before any fetch is attempted — even
  when the alias is a real, reachable sparse-index registry.
- The `deps_core::Registry` trait's five network-performing methods
  (`get_versions`, `get_versions_with`, `get_latest_matching`,
  `get_latest_matching_with_context`, `search` —
  `crates/deps-core/src/registry.rs:83,106,141,162,179`) all take a bare
  `&PackageName`. `CargoEcosystem::registry()` returns one
  `Arc<dyn Registry>` per ecosystem (not per document), so nothing in the
  current pipeline can carry "which registry does *this* dependency
  belong to" from the parser into the fetch.
- A consequence, verified live: `fetch_latest_versions_parallel`
  (`crates/deps-lsp/src/document/lifecycle.rs:665`) and the dedup at
  `lifecycle.rs:1079-1085` are name-keyed with no source filter, so a
  private-registry dependency's **name** is sent to `index.crates.io`
  today, even though the resulting (wrong) data is never shown — an
  unintended privacy leak that this feature also closes as a side effect
  of fixing the routing.

This gap is silent: nothing tells a user why their `registry = "my-corp"`
dependency shows no hover/diagnostic/completion data, so it reads as a bug
rather than a documented limitation. The identical gap exists in every
other ecosystem crate this LSP supports (npm `.npmrc`, Maven
`settings.xml`, NuGet feeds, Composer `repositories`, Bundler `source`
blocks) — this spec's reference pattern (parser resolves alias to a
concrete index URL → formatter gates on it → registry router dispatches on
it → per-registry client no-ops search) is intended to be copied by those
follow-ups, not reinvented.

This spec is the product of two architect design rounds and two adversarial
critic reviews (`.local/handoff/2026-09-01T15-05-25-architect.md` through
`2026-09-01T15-21-35-critic.md` in the `feat/431-cargo-custom-registries`
worktree). The design converged on `significant` (no remaining structural
issues) after the second critic pass; the requirements below fold in every
blocking (C1-C3) and must-land (R1-R3) finding from that review as concrete,
testable functional requirements, not left as open design questions.

> [!warning] Assumptions
> - Users' private/custom registries speak the sparse index protocol
>   (`sparse+https://`) — the same JSON-lines wire format `deps-cargo`
>   already parses for crates.io. Git-index (legacy) registries are not
>   addressed and remain unsupported, matching today's behavior exactly
>   (no regression, no new capability).
> - Users store registry tokens the way Cargo itself expects
>   (`CARGO_REGISTRIES_<NAME>_TOKEN` env var, or `$CARGO_HOME/config.toml`),
>   not committed to the repository being opened.

### Goal

A Cargo dependency resolved against a `.cargo/config.toml`-declared
registry, or against a workspace's `[source]` replace-with target, gets the
same hover/diagnostic/completion value a crates.io dependency gets — with
zero regression for workspaces that declare no custom registry, and with no
credential ever attachable to a request whose destination URL was declared
by a file inside the repository being opened.

### Out of Scope

> [!danger] Explicit Exclusions
> - **Git dependency in-use-version-from-`Cargo.lock` and tag-checking**
>   ("Phase 3a/3b" in the design handoffs) — `parse_cargo_source`
>   (`crates/deps-cargo/src/lockfile.rs:166`) already yields
>   `ResolvedSource::Git { url, rev }` and the lock entry already carries a
>   version; hover shows nothing purely because of the same
>   `is_version_resolvable` gate this spec replaces. Zero network,
>   highest value-per-line item the design review identified — but the
>   user decided this spec ships full Phase 1 (registries + replace-with)
>   first, and Phase 3a/3b is filed as a **separate follow-up issue** after
>   this spec lands, not designed here.
> - **Private crate *name* search/completion** (`complete_package_names`)
>   — the sparse index protocol has no search endpoint; this is
>   protocol-inherent, not an implementation gap deferred by choice.
> - **Git-index (non-sparse) registries** — remain unsupported, identical
>   to today's behavior.
> - **`credentials.toml` / the Cargo credential-provider plugin chain.**
> - **`(registry, name)` cache-key widening** — the same-name-two-
>   registries bail-out (FR-011 below) covers v1; file as a follow-up if
>   npm scoped registries later need the wider key
>   (`crates/deps-lsp/src/document/lifecycle.rs:1079` gets a
>   `// TODO(critic):` marker per the design review's D1 item).
> - **A dedicated `.cargo/config.toml` file watcher** — see FR-013's
>   normative resolution below; this spec chooses documentation over a new
>   watcher subsystem for v1.

## 2. User Stories

### US-001: Private registry version resolution

AS A developer with a dependency on my company's private Cargo registry
I WANT hover, diagnostics, and completion to work for it
SO THAT I get the same LSP value I get for crates.io dependencies

**Acceptance criteria:**
```
GIVEN a Cargo.toml with foo = { version = "1.0", registry = "my-corp" }
  AND a .cargo/config.toml with [registries.my-corp]
      index = "sparse+https://index.mycorp.dev"
WHEN I hover over the foo dependency
THEN the hover shows the latest version available on index.mycorp.dev,
     not crates.io, and no request is sent to index.crates.io for "foo"
```

### US-002: Mirrored workspace resolution via `[source]` replace-with

AS A developer whose team redirects crates.io through a corporate mirror
I WANT plain dependencies to resolve against the mirror
SO THAT hover/diagnostics reflect what my team's mirror actually serves

**Acceptance criteria:**
```
GIVEN [source.crates-io] replace-with = "my-mirror"
  AND [source.my-mirror] registry = "sparse+https://mirror.corp.example/"
WHEN I hover over any plain dependency
THEN the hover reflects my-mirror's index data
```

### US-003: No regression for vendored/git-index workspaces

AS A developer using a vendored (`directory`) or git-index mirror
I WANT the LSP to keep behaving exactly as it does today
SO THAT I don't lose working functionality because of this feature

**Acceptance criteria:**
```
GIVEN [source.crates-io] replace-with = "vendored"
  AND [source.vendored] directory = "vendor/"
WHEN I hover over a plain dependency
THEN the hover is byte-identical to pre-feature behavior (crates.io fallback)
```

### US-004: Credentials never leak to a workspace-controlled destination

AS A developer opening an untrusted cloned repository
I WANT no credential ever sent to a URL that repository's own files declare
SO THAT cloning and opening a hostile repo cannot exfiltrate my tokens

**Acceptance criteria:**
```
GIVEN a repository whose .cargo/config.toml declares a registry pointing at
     an attacker-controlled host, aliased "github"
  AND my own environment happens to have CARGO_REGISTRIES_GITHUB_TOKEN set
     (for an unrelated, legitimately $CARGO_HOME-declared "github" registry)
WHEN the LSP resolves the repository's "github"-aliased dependency
THEN no Authorization header is ever sent to the attacker-controlled host —
     the token is attached only to requests whose resolved index URL
     provenance is $CARGO_HOME/config.toml, never a workspace file
```

## 3. Functional Requirements

Every requirement below traces to a specific blocking (C1-C3) or must-land
(R1-R3, M1, M4, M6-M9) finding from the design review
(`.local/handoff/2026-09-01T15-21-35-critic.md`), cited inline. FR-001
through FR-004, FR-008-FR-012, FR-014-FR-016 ship in **PR 1a**; FR-005
through FR-007 ship in **PR 1b** — see [[plan#Sequencing]] for the
binding rationale.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN any `Registry` trait method that performs a network request is called for a dependency whose source is a resolved `AlternateRegistry` THE SYSTEM SHALL route that specific call to the alternate registry's index — covering `get_versions`/`get_versions_with` via a new `get_versions_from` AND `get_latest_matching`/`get_latest_matching_with_context` via a new `get_latest_matching_from`; `search` stays crates.io-only, documented as unreachable for alternate sources (sparse protocol has no search endpoint) *(closes C1/R1 — the routing enumeration was incomplete twice during design review, first missing all five network methods, then missing the `get_latest_matching`/`get_latest_matching_with_context` fallback paths at `hover.rs:187` and `lifecycle.rs:760`)* | must |
| FR-002 | WHEN a `Cargo.toml` dependency declares `registry = "<alias>"` or `registry-index = "sparse+https://..."` AND a matching `.cargo/config.toml` hierarchy entry resolves to a valid `https`, non-userinfo URL THE SYSTEM SHALL represent that dependency's source as `DependencySource::AlternateRegistry { index }`, a new variant distinct from the existing `CustomRegistry { url }` (which keeps meaning "unresolved alias") *(closes S2 — makes "resolved" a type-level state instead of string-sniffing `starts_with("http")`)* | must |
| FR-003 | WHEN alias resolution fails (no matching config entry, invalid URL, non-https, userinfo present) THE SYSTEM SHALL leave the source as `DependencySource::CustomRegistry { url: <alias> }` unchanged and emit a `tracing::warn!` distinguishable from FR-011's collision warning | must |
| FR-004 | WHEN `$CARGO_HOME` is not set in the process environment THE SYSTEM SHALL NOT attempt to read any path derived from `HOME`/`USERPROFILE`, and shall not add a `dirs`/`home` crate dependency to support such a fallback *(closes M2 — no such crate exists anywhere in this workspace today)* | must |
| FR-005 | WHEN a `[source]` replace-with chain resolves (via a two-stage process: alias → source id, then source-replacement chain, bounded iteration + visited-set cycle check) to a `sparse+https://` index THE SYSTEM SHALL reroute plain (`Registry`-sourced) dependencies to that index | must (1b) |
| FR-006 | WHEN a `[source]` replace-with chain resolves to a `directory` (vendored), `local-registry`, or non-sparse git-index source THE SYSTEM SHALL keep resolving plain dependencies against crates.io, unchanged from today *(closes C3, corrected per M6: Cargo verifies per-version checksums for replacements, it does NOT enforce full content-set equivalence — for a vendored source the version *set* is not equivalent to crates.io's, since the vendor dir holds only what `Cargo.lock` pinned; the fallback may therefore surface "Outdated" suggestions for versions absent from the vendor dir, identical to today's behavior, not a regression, and documented as such)* | must (1b) |
| FR-007 | WHEN a `[source]` replace-with graph is cyclic or self-referential THE SYSTEM SHALL terminate resolution via bounded iteration and a visited-set check rather than looping, reusing the depth-guard standard already applied workspace-wide for untrusted JSON parsing (#432) *(closes S4)* | must (1b) |
| FR-008 | WHEN a registry's index URL was resolved from `$CARGO_HOME/config.toml` THE SYSTEM SHALL attach its resolved bearer token (from `CARGO_REGISTRIES_<NAME>_TOKEN` or `$CARGO_HOME/config.toml` itself) to requests against that index | must |
| FR-009 | WHEN a registry's index URL was resolved from any workspace file (the `Cargo.toml` alias target, any ancestor `.cargo/config.toml` within the workspace) THE SYSTEM SHALL resolve the token **at config-load time** into `auth: Option<AuthToken>` on that entry, populated **only** on the `$CARGO_HOME` branch, such that no downstream fetch code path has API surface through which to obtain a token for a workspace-declared entry *(closes C2 per the user's binding decision, hardened by R3: the first design draft proposed a runtime `Provenance` check at the call site, which the final critic re-verification identified as forgeable — "an enum field plus a conditional... is exactly a runtime check that can be forgotten at a call site." A `Provenance { CargoHome, Workspace }` enum may still exist for logging, but it must never gate auth attachment)* | must — security-blocking |
| FR-010 | WHEN an authenticated request to an alternate index is made THE SYSTEM SHALL route it through a new `HttpCache::get_cached_trusted_origin_with_headers(url, trusted_origin, headers)` — an origin-pinned accessor composing the existing private `get_cached_with_headers_via` (`cache.rs:489`) with the existing `client_for_origin` (`cache.rs:371`) — so that an `Authorization` header cannot survive a cross-origin redirect hop, by construction, with no empirical test required *(closes S6, dissolves the original open question about reqwest's cross-origin header-stripping behavior)* | must |
| FR-011 | WHEN one document declares the same package name against two different resolved registries THE SYSTEM SHALL skip version resolution for **all** occurrences of that name and log a `tracing::warn!` naming both resolved index URLs, using message text distinguishable from FR-003's unresolvable-source warning *(closes M1 — prevents a genuine resolution bug, which yields two different resolved strings for what should be one registry, from being silently indistinguishable from this legitimate collision)* | must |
| FR-012 | WHEN `CompletionContext::Version`/`Feature`'s `package_name` is joined against `parse_result.dependencies()` (entirely inside `deps-cargo`'s `generate_completions`, `crates/deps-cargo/src/ecosystem.rs:148`, with zero `deps-core` signature change) and that name is ambiguous per FR-011's collision condition THE SYSTEM SHALL offer no version/feature completions for that name and warn, reusing FR-011's bail-out rather than picking a match arbitrarily *(closes C1's completion concern, corrected: version/feature completion IS in-scope, since `complete_versions`/`complete_features` are private inherent methods reachable via the already-`parse_result`-carrying `generate_completions`; only `complete_package_names` stays out of scope, per M7 for the ambiguity tie-break)* | must |
| FR-013 | THE SYSTEM SHALL resolve `.cargo/config.toml` staleness handling via **option (b): no dedicated file watcher.** `ECOSYSTEM_GUIDE.md` documents that editing `.cargo/config.toml` does not take effect until the affected `Cargo.toml` is otherwise reparsed (edited, or the document reopened) *(closes R2, which established that "add a glob pattern to the existing lock-file watcher" does not work — every event in `did_change_watched_files`, `crates/deps-lsp/src/server.rs:496-522`, is routed through `extract_lockfile_name` → `EcosystemRegistry::get_for_lockfile`, which silently drops anything that does not resolve as a known lockfile name; registering `config.toml` as a fake lockfile name would instead misroute the event into the Cargo lockfile-change handler. Option (a) — a dedicated watcher branch with its own reparse-scope computation — is a second new subsystem this P4-priority spec declines to build for v1; see [[plan]] for the full rationale and the upgrade path if live usage shows this insufficient)* | must — the choice itself, not a specific mechanism, is mandatory |
| FR-014 | WHEN the resolved dependency source is not crates.io THE SYSTEM SHALL suppress `CargoFormatter::package_url`/`crate_url`'s hover heading link *(closes M5 — with live version data now rendered beside it, a crates.io link for a private crate reads as confirmation the link is real, worse than today's inert hover)* | must |
| FR-015 | WHEN `CARGO_REGISTRIES_<NAME>_INDEX`/`_TOKEN` derived env-var names collide across two distinct aliases (e.g. `my-corp` and `my_corp` both map to `CARGO_REGISTRIES_MY_CORP_INDEX`) THE SYSTEM SHALL ignore the env override for **both** aliases and log a warning naming both *(closes M4 — a deliberate, documented divergence from Cargo's own arbitrary-pick behavior on this collision)* | must |
| FR-016 | THE SYSTEM SHALL add `EcosystemFormatter::can_resolve_source(&DependencySource) -> bool`, defaulted to `source.is_version_resolvable()`, overridden **only** by `CargoFormatter`, and migrate the 8 existing `is_version_resolvable()` call sites (`diagnostics.rs:498,508,540,584,611`, `hover.rs:63`, `code_actions.rs:202`) to it, **not** placing the hook on `Registry` *(closes S1 — a `Registry`-level hook would ripple into 6+ unrelated call sites including `deps-pypi/src/ecosystem.rs:1142` and the external `deps-gradle/tests/integration_tests.rs:226`, and would inject a registry handle into `generate_diagnostics_from_cache`, which is deliberately registry-free by design; `EcosystemFormatter` is already a parameter of all three affected functions and already carries this class of gate, e.g. `yanked_diagnostic_applies_to`)* | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No credential is attachable to a request whose destination provenance traces to a workspace file, under any code path — verified by code inspection (grep for `Provenance` usage outside `config.rs`, confirming it never gates auth attachment) in addition to tests, per FR-009's structural (not runtime) requirement |
| NFR-002 | Security | Every resolved index URL passes a `RegistryIndex` newtype (built on the `url` crate, promoted from dev-dependency to a real `deps-cargo` dependency) that rejects non-https schemes and userinfo-bearing URLs at construction, before any network request — this is SSRF-adjacent input, since a workspace file controls a network destination |
| NFR-003 | Security | Residual risk, non-blocking, must be stated for security-reviewer sign-off before 1a merges (per M9): even with NFR-001/002 satisfied, an *unauthenticated* HTTPS GET to a workspace-declared index still occurs, which is reachability into the user's internal network (RFC1918 hosts, internal PKI endpoints) usable for existence probing by a hostile repository, and the response lands in the shared `HttpCache`. This is the same trust model Cargo itself has on `cargo build`, but an LSP auto-parses on file open — an earlier trust boundary. The design explicitly declined an opt-in gate for this (not needed to close the credential-exfiltration path, which `$CARGO_HOME`-only auth already closes) — routed to the security reviewer's judgment, not blocking this spec |
| NFR-004 | Performance | PR 1a: config discovery adds zero additional FS reads when no dependency in the manifest carries `registry`/`registry-index` (the lazy-trigger optimization remains valid in 1a because 1a excludes `[source]` replace-with) |
| NFR-005 | Performance | PR 1b: since replace-with affects *plain* dependencies (i.e., every manifest), the lazy trigger no longer holds once 1b lands; config resolution must be memoized keyed on workspace root, invalidated by the mtime of every file that contributed to the resolution, with a stated cap on ancestor-walk depth *(closes S3)*. `find_workspace_root` (`crates/deps-cargo/src/parser.rs:357`) already performs the ancestor walk needed — config-path collection piggybacks on that same pass, so the walk itself is not new, only the extra reads are |
| NFR-006 | Maintainability | The routing surface's exhaustiveness (FR-001) is verified by a **mockito test asserting the alternate index is hit specifically on the hover-fallback path** (`hover.rs:187`'s `get_latest_matching_from` call) and the background-fetch-mirror path (`lifecycle.rs:760`), not only the happy-path `get_versions_from` call — this exact enumeration has been wrong twice already during design review and must not be verified by implementation-time grep a third time |
| NFR-007 | Maintainability | `CargoRegistry.alternates: DashMap<RegistryIndex, Arc<SparseIndexClient>>` is capped per workspace root at a bound in the low hundreds of entries (e.g. 256 — generous for any realistic `.cargo/config.toml` registry count, exact number left to implementation) — otherwise unbounded, keyed by workspace-controlled URLs, for the process lifetime *(closes M8)* |
| NFR-008 | Reliability | Zero behavior change for any workspace declaring no custom registry and no `[source]` replace-with — verified by the existing `deps-cargo` test suite passing unmodified |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencySource::AlternateRegistry` | New `deps-core` variant — a *resolved* registry source | `index: String` (validated, `sparse+`-stripped index URL) |
| `DependencySource::CustomRegistry` | Existing variant, meaning unchanged — an *unresolved* alias | `url: String` (in fact the bare alias, e.g. `"my-corp"`) |
| `RegistryIndex` | New `deps-cargo` newtype — validated index URL | Built on `url::Url`; enforces https, no userinfo, strips `sparse+` prefix at construction |
| `CargoConfig` | New `deps-cargo` type — merged resolved `.cargo/config.toml` hierarchy | `registries: HashMap<alias, ResolvedRegistryEntry>` (1a), `source: HashMap<name, SourceEntry>` (1b) |
| `ResolvedRegistryEntry` | New `deps-cargo` type — one resolved `[registries.<name>]` entry | `index: RegistryIndex`, `auth: Option<AuthToken>` (populated only when `$CARGO_HOME`-declared, per FR-009), `provenance: Provenance` (diagnostics only, never an auth gate) |
| `AuthToken` | New `deps-cargo` newtype wrapping a registry bearer-token credential | A single `String` field holding the raw token value; `Debug` and `Display` are hand-implemented to redact it (e.g. print `AuthToken(***)`), never the raw value, so it cannot leak via logs, panics, or error messages; constructed **only** inside the `$CARGO_HOME`-branch of config resolution (`config.rs`), per FR-009/R3 — no other code path has the means to construct one |
| `Provenance` | New `deps-cargo` enum — `{ CargoHome, Workspace }` | Diagnostic/logging use only |
| `SparseIndexClient` | New `deps-cargo` type — extracted from the existing crates.io client | `base_url`; owns `sparse_index_path`/`parse_index_json` (moved, not reimplemented) |
| `CratesIoRegistry` | Existing type, narrowed | `SparseIndexClient` + crates.io search REST API + `crate_url` |
| `CargoRegistry` | New `deps-cargo` type — the `Registry` impl behind `CargoEcosystem::registry()` | `crates_io: CratesIoRegistry`, `alternates: DashMap<RegistryIndex, Arc<SparseIndexClient>>` (capped, NFR-007), `cache: Arc<HttpCache>` |
| `Registry::get_versions_from` / `get_latest_matching_from` | New defaulted trait methods on `deps-core::Registry` | Default to the existing non-source-aware methods; overridden only by `CargoRegistry` |
| `EcosystemFormatter::can_resolve_source` | New defaulted trait method | Default `source.is_version_resolvable()`; overridden only by `CargoFormatter` |
| `HttpCache::get_cached_trusted_origin_with_headers` | New public method on `deps-core::HttpCache` | Composes existing private `get_cached_with_headers_via` + `client_for_origin`; cache-key invariant: one `Authorization` value per index URL (key stays URL-only) |

**Cargo dependency changes**: `crates/deps-cargo/Cargo.toml` — `url`
(currently `[dev-dependencies]` only, confirmed at line 34) moves to
`[dependencies]`; `dashmap = { workspace = true }` (already pinned at the
workspace level, used by `deps-core`/`deps-npm`/`deps-maven`/`deps-lsp`/
`deps-swift`, not currently a `deps-cargo` dependency) is added to
`[dependencies]`. Both inserted alphabetically per
`.claude/rules/dependencies.md`.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Alias declared, no `.cargo/config.toml` entry | Stays `CustomRegistry { url: alias }`; `tracing::warn!`; dependency shows no version data (today's behavior), no crash |
| `registry-index` URL is `http://` or carries userinfo | `RegistryIndex` construction fails; source stays unresolved; warn logged (FR-003) |
| Same name declared against two registries in one manifest | Both occurrences skipped; distinct warn naming both resolved URLs (FR-011) |
| `[source]` replace-with cycle | Bounded iteration + visited-set stops the loop; treated as unresolved for that chain, warn logged (FR-007) |
| `$CARGO_HOME` unset | No `HOME`/`USERPROFILE` fallback attempted; `$CARGO_HOME`-tier config contributes nothing (FR-004) |
| `CARGO_REGISTRIES_MY_CORP_INDEX` ambiguous between `my-corp`/`my_corp` | Override ignored for both; warn naming both aliases (FR-015) |
| Alternate registry unreachable / times out | Dependency shows no version data; no panic; identical shape to crates.io-unreachable handling today |
| `.cargo/config.toml` malformed TOML | That file's contributions fail closed; other hierarchy levels still apply; warn logged |
| `.cargo/config.toml` edited after initial resolution | Stale until the affected `Cargo.toml` is next reparsed (FR-013, documented limitation) |
| Vendored (`directory`) replace-with | Crates.io fallback continues (no regression); may show "Outdated" for versions absent from the vendor dir — documented with the precise M6 rationale ("checksum-verified per version, not equivalent in version set") |
| Dependency declared twice against different registries, in a completion context | No version/feature completions offered for that name (FR-012) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Private-registry dependency shows live hover/diagnostic/completion data | Pass on a real or mocked sparse-index fixture |
| SC-002 | Zero regression on crates.io-only workspaces | Existing `deps-cargo` test suite passes unmodified |
| SC-003 | No credential reaches a workspace-declared destination | Security-review sign-off + FR-009 structural test + `Provenance`-usage grep |
| SC-004 | Routing surface exhaustively covered | Mockito test passes specifically on the hover-fallback (`hover.rs:187`) and background-fetch-mirror (`lifecycle.rs:760`) paths, not only the happy path — the blocking acceptance gate per NFR-006 |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets
  --all-features --workspace -- -D warnings`, `cargo nextest run
  --workspace --all-features` before considering a task complete.
- Follow the Registry Integration Gate
  (`.claude/rules/continuous-improvement.md`) — verify against a real or
  mocked sparse index before filing the implementation PR.
- Update `CHANGELOG.md`, `ECOSYSTEM_GUIDE.md`,
  `.local/testing/coverage.md` (cargo row),
  `.local/testing/playbooks/cargo.md`, `.local/testing/regressions.md`.
- Extend `SparseIndexClient` rather than reimplementing sparse-index
  parsing; extend `EcosystemFormatter` rather than adding a
  `Registry`-level gate.

### Ask First
- Implementing FR-013's option (a) (a dedicated config-file watcher)
  instead of the documented-limitation option (b) this spec adopts — a
  scope increase beyond what this spec specifies.
- Any change to the `$CARGO_HOME`-only auth trust rule (FR-008/FR-009) —
  the security-blocking requirement; do not weaken it to unblock an
  implementation difficulty.
- Widening the `deps-core` `Registry`/`EcosystemFormatter` trait surface
  beyond the two new defaulted methods and one hook specified here.

### Never
- Attach a credential to a request whose destination URL provenance traces
  to a workspace file, under any code path.
- Match exhaustively on `DependencySource` in new production code without
  a `_ => ...` fallback arm — the low-risk-variant-addition property this
  spec relies on (verified: every existing exhaustive match is
  `#[cfg(test)]` with a `_ => panic!()` arm) depends on that convention
  holding.
- Add a `dirs`/`home` crate dependency to work around `$CARGO_HOME` being
  unset.
- Skip the mockito tests on the hover-fallback / background-fetch-mirror
  paths specifically (FR-001/SC-004) — a happy-path-only test has already
  produced two false "done" signals in this design's review history.

## 9. Open Questions

None blocking, and NFR-003's residual is now resolved. PR #447 answered it not
with an opt-in `DepsConfig` gate but with a new `deps-core::net_policy`
host classifier (`HostClass`/`classify_host`) gated by a `cargo.workspace_registries`
setting (`off`/`public_only`/`all`, default `public_only`), applied to every
workspace-declared registry/source URL and every redirect hop — see
[[024-net-policy-dns-rebinding/spec|024-net-policy-dns-rebinding]] for the
follow-up DNS-rebinding hardening on top of that classifier (PRs #457/#460).

## 10. See Also

- [[constitution]] — project principles (not yet created for this
  project; cross-checked against `.claude/rules/*.md` instead, see
  [[plan#10. Constitution Compliance]])
- [[MOC-specs]] — all specifications
- [[024-net-policy-dns-rebinding/spec|024-net-policy-dns-rebinding]] — the
  DNS-rebinding follow-up hardening built on top of PR #447's `net_policy`
- [[023-cargo-custom-registries/plan|plan]] — technical plan, 1a/1b PR
  sequencing, task-level detail
- PR #440 — shipped PR 1a (registries), closes issue #431
- PR #447 — shipped PR 1b (source replace-with) + NFR-003 SSRF sign-off,
  closes issue #443
- `crates/deps-core/src/parser.rs` — `DependencySource`,
  `is_version_resolvable`
- `crates/deps-core/src/registry.rs` — `Registry` trait
- `crates/deps-core/src/cache.rs` — `HttpCache`,
  `get_cached_trusted_origin`
- `crates/deps-cargo/src/registry.rs`, `crates/deps-cargo/src/parser.rs`,
  `crates/deps-cargo/src/formatter.rs`, `crates/deps-cargo/src/
  ecosystem.rs`
- `crates/deps-lsp/src/document/lifecycle.rs`,
  `crates/deps-lsp/src/server.rs`
- Design review handoffs (`feat/431-cargo-custom-registries` worktree,
  `.local/handoff/`): `2026-09-01T15-05-25-architect.md`,
  `2026-09-01T15-09-21-critic.md`, `2026-09-01T15-18-17-architect.md`,
  `2026-09-01T15-21-35-critic.md`
- Issue #431

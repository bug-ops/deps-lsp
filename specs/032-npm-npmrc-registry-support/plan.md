---
aliases:
  - npm .npmrc Registry Support Plan
tags:
  - sdd
  - plan
  - enhancement
  - security
  - npm
created: 2026-09-02
status: draft
related:
  - "[[spec]]"
  - "[[023-cargo-custom-registries/plan|023-cargo-custom-registries plan]]"
---

# Technical Plan: npm `.npmrc` Custom/Private Registry Support

> [!info] References
> **Spec**: [[spec]]
> **Reference implementation**: [[023-cargo-custom-registries/plan|023-cargo-custom-registries]] —
> this plan reuses that implementation's architecture (parse-time source
> resolution, `AlternateRegistry`, `alternates` router map,
> `can_resolve_source`, `net_policy` gating, source-routed completion) wherever
> npm's simpler, unauthenticated, two-tier config model allows it, and diverges
> only where npm's own format or trust model genuinely differs (see §1 Key
> Design Decisions).

> [!note] Revision history
> **r3 (2026-09-02)** — revised against a second `critical` verdict
> (`.local/handoff/2026-09-02T19-32-08-critic.md`). Fixes N-C1 (r2 inverted
> S6's disposition and mandated a release-build `http`-loopback exception that
> `deps-core` rejects anyway), N-S1 (unregistered-`AlternateRegistry` fetch
> fallthrough), N-S2 (config-rename blast radius and the CHANGELOG wording it
> implies) and N-M1/N-M2/N-M3. §12 carries both disposition tables.
>
> **r2 (2026-09-02)** — revised against the first `critical` verdict
> (`.local/handoff/2026-09-02T19-15-42-critic.md`). Every finding C1-C3,
> S1-S6, M1-M9 addressed, plus two gaps found while re-verifying (A1, A2).
> Its S6 disposition was wrong; see N-C1.

## 1. Architecture

### Approach

Same parse-time resolution strategy as Cargo (023): `NpmParser` gains `.npmrc`
discovery (project-tier ancestor walk + user-tier `~/.npmrc`) and rewrites each
dependency's `DependencySource` according to the merged config. Every dependency
lands in exactly one of three existing `deps-core` states — **no new
`DependencySource` variant, and no `deps-npm`-local source enum**:

| Config outcome for this dependency | Resolved `DependencySource` | Downstream effect |
|---|---|---|
| No `registry=`/`@scope:registry=` applies (FR-005) | `Registry` (today's behavior, unchanged) | Public registry, byte-identical to pre-feature |
| A matching entry present, validated, policy-allowed (FR-003/FR-004) | `AlternateRegistry { index: <normalized url>, mirrors_crates_io: false }` | Routed to the alternate client |
| A matching entry present but invalid, unexpandable, or policy-blocked (FR-006/FR-007/FR-008) | `CustomRegistry { url: <raw value as written> }` | `is_version_resolvable() == false` → fails closed everywhere |

The third row is the C1 fix. `DependencySource::CustomRegistry { url }` is
documented in `crates/deps-core/src/parser.rs:875-882` as *"always means 'not yet
resolved to a concrete index this LSP can query' — `url` may hold a bare alias
or a URL string, but never a value this LSP has validated and can fetch
against"*, and `parser.rs:944`'s `is_version_resolvable()` returns `false` for
it. That is precisely npm's failed-validation state. The previous revision
rejected this variant on the grounds that "npm never has a named-but-not-yet-
looked-up alias state" — that misread the variant's contract, which is about
*resolvability*, not about aliases. Reusing it costs zero `deps-core` change and
inherits every already-shipped fail-closed path (diagnostics, hover, code
actions, background fetch) for free.

Everything downstream then reads the already-resolved source. That premise holds
for hover, diagnostics, code actions and the background fetch — all of which
already route through `get_versions_from`/`get_latest_matching_from`
(`deps-core/src/lsp_helpers/hover.rs:84,216`,
`code_actions.rs:583`, `deps-lsp/src/document/lifecycle.rs:1094,1165`). It does
**not** hold for version completion, which today calls the source-blind
`Registry::get_versions_with` (`crates/deps-core/src/completion.rs:875`) — see
the FR-017 decision below.

### Component Diagram

```mermaid
graph TD
    PJ["package.json"] -->|parse| P[NpmParser]
    NC[".npmrc project tier (ancestor walk)<br/>+ ~/.npmrc user tier"] -->|discover, merge| CFG[NpmConfig]
    CFG -->|resolve_source_for(name)| P
    P -->|"Registry | AlternateRegistry | CustomRegistry"| DEP[Dependency]
    P -->|"resolved_registries: Vec&lt;NpmRegistryIndex&gt;"| REG

    DEP --> HOV["hover.rs"]
    DEP --> CA["code_actions.rs"]
    DEP --> LC["lifecycle.rs<br/>fetch_latest_versions_parallel"]
    DEP --> COMP["ecosystem.rs<br/>resolve_completion_source (FR-017)"]

    HOV --> REG[NpmRegistry router]
    CA --> REG
    LC --> REG
    COMP -->|alternate_client(index)| REG

    REG -->|"tier = Public"| PUBC["get_cached_with_headers"]
    REG -->|"tier = WorkspaceDeclared"| WSC["get_cached_workspace_with_headers (NEW)"]

    PUBC --> HC[HttpCache]
    WSC --> HC

    FMT[NpmFormatter] -->|"can_resolve_source / suppress_package_url"| DIAG["generate_diagnostics_from_cache<br/>generate_hover"]
```

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|--------------------------|
| **Where "unresolved" (FR-006 fail-closed) lives** (C1, M8 — row fully rewritten) | Reuse the existing `DependencySource::CustomRegistry { url: <raw .npmrc value> }`. No new `deps-core` variant, no `deps-npm`-local source enum, and no `RegistryResolution` intermediate type — `NpmConfig::resolve_source_for(&PackageName) -> DependencySource` returns the final variant directly and the parser assigns it. | `CustomRegistry`'s documented contract is exactly "present, but not resolved to a concrete index this LSP can query" (`deps-core/src/parser.rs:875-882`), and `is_version_resolvable()` is already `false` for it (`parser.rs:944`). Every fail-closed consumer — `can_resolve_source`'s default, diagnostics' 8 migrated gates, `get_versions_for_source`'s fallthrough — already treats it correctly. Zero `deps-core` change, and it satisfies the spec's "never widen the `deps-core` `Registry`/`EcosystemFormatter` trait surface" boundary outright. Retaining the raw string in `url` keeps the warning log and any future diagnostic message able to name what the user actually wrote. | (a) A new `DependencySource::UnresolvedAlternateRegistry` variant — rejected, it would duplicate `CustomRegistry`'s meaning verbatim and force every ecosystem's `match` to grow an arm. (b) A `deps-npm`-local `RegistryResolution{Public,Alternate,Unresolved}` enum mapped in the parser — rejected as pure indirection: it has a total, information-preserving mapping onto the three `DependencySource` variants, so it is a type that exists only to be immediately destructured. (c) Leave the source as plain `Registry` — rejected outright, that *is* the #248 silent-public-fallback bug. |
| **Policy scope: one shared setting, not `npm.workspace_registries`** (C2, user decision) | Rename `cargo.workspace_registries` → **`registries.workspace_registries`** (new top-level `RegistriesConfig` section; `CargoConfig` is deleted, since `workspace_registries` was its only field). One setting, governing every ecosystem's workspace-declared registry fetches. | `HttpCache` holds exactly one `Arc<RegistryAccessPolicy>` and one workspace `Transport`, rebuilt by a single global `set_registry_policy` (`deps-core/src/cache.rs:1060`); `ServerState::new` shares that one handle with `register_ecosystems` (`deps-lsp/src/document/state.rs:494-508`). Two independent settings writing it (`server.rs:391,523`) would be last-writer-wins, and `npm.workspace_registries = "all"` would silently widen Cargo's already-shipped SSRF gate (#449/#453/#457/#460) — a security regression. Given one global policy object, a config key named after one ecosystem is a lie about its blast radius; renaming it makes the shipped behavior and the key name agree. Per-ecosystem policy would need an `HttpCache`/`Transport` refactor (one transport per policy), explicitly out of this spec's scope. Pre-1.0, so no compatibility shim (project CLAUDE.md). | (a) Keep the literal key `cargo.workspace_registries` and document it as governing npm too — rejected: an npm-only user has no reason to look under `cargo.*`, and the key would be actively misleading in the one place (`README`/`ECOSYSTEM_GUIDE`) users read it. (b) Accept both keys, `cargo.*` as a deprecated alias — rejected: pre-1.0 explicitly forbids compatibility shims, and `DepsConfig` carries `#[serde(deny_unknown_fields)]`, so an alias means two live fields plus a merge rule for the case where they disagree. (c) Per-ecosystem policy inside `HttpCache` — the architecturally correct end state, but it means N transports and a policy-keyed transport cache; deferred to its own spec, noted in §11 Risks. |
| **`${VAR}` expansion in a registry URL value** (S4, user decision) | A **defined** `${VAR}` in a `registry=`/`@scope:registry=` value **is** expanded from the LSP server's process environment, then the expanded string goes through the ordinary `NpmRegistryIndex::new` validation. An **undefined** `VAR` makes the whole value invalid per FR-007 → `CustomRegistry`. Expansion applies **only** to these two key shapes; no auth-shaped key is ever parsed, so no credential is ever expanded (FR-013/NFR-001 untouched). | This is npm's own documented `.npmrc` behavior, and `registry=${NPM_REGISTRY}` is a real pattern in CI-parameterized monorepos. Refusing every `${...}`-containing value would silently disable the feature for those workspaces with no diagnosable reason. The expanded value is not trusted: it is a *candidate*, subject to the same https/no-userinfo/`classify_host` gate as a literal one, so the environment can only select among URLs the policy already permits — it cannot bypass the gate. | (a) Reject any `${...}`-containing value outright — rejected, breaks a common legitimate pattern and diverges from npm without a security gain (the policy gate, not the literal-string requirement, is what bounds reachability). (b) Expand from a curated allow-list of variable names — rejected, no principled list exists and it adds config surface for no gain. |
| **FR-017: version-completion routing** (C3 — new) | Mirror Cargo exactly, adapted to npm's scope-keyed resolution: a private `CompletionSource { NotInManifest, Resolved(DependencySource), Ambiguous }` enum plus `resolve_completion_source(parse_result, package_name)` in `deps-npm/src/ecosystem.rs`, and `NpmRegistry::alternate_client(&str) -> Option<Arc<NpmRegistry>>`. `NpmEcosystem::complete_versions` gains a `parse_result: &dyn ParseResult` parameter and dispatches: `NotInManifest`/`Resolved(Registry)` → today's `complete_versions_generic(self.registry, ..)`; `Resolved(AlternateRegistry{index,..})` → `complete_versions_generic(alternate_client(&index), ..)`, or no completions if unregistered; `Ambiguous` and every other `Resolved(_)` (including `CustomRegistry`) → no completions. | Without this, typing a version for `"@myorg/internal-lib"` sends the private package name to `registry.npmjs.org` — the same leak class FR-006 closes for hover/diagnostics. `generate_completions` **already** receives `parse_result` (`deps-core/src/ecosystem.rs:651`, `deps-npm/src/ecosystem.rs:124`), so this is entirely internal to `deps-npm`: no `deps-core` signature change. The npm adaptation is only in *what* resolution keys off — Cargo joins on an explicit per-dependency `registry` alias, npm joins on the same already-parsed dependency's `source`, which the parser derived from the `@scope/` name prefix. The name-join, ambiguity rule, and bail-out semantics are identical (`deps-cargo/src/ecosystem.rs:40-190`, `deps-cargo/src/registry.rs:487`). | (a) Make `complete_versions_generic` source-aware in `deps-core` — rejected, it would change a shared signature for two of eleven ecosystems and push `DependencySource` matching into a generic helper. (b) Leave completion public-only and document the leak — rejected, it is the same silent-exfiltration class the spec's "Never" boundary forbids. (c) Skip completion for *any* manifest that has a `.npmrc` — rejected, over-broad: an unaffected public dependency in that manifest would lose completions for no reason. |
| **FR-011: package-*name* search/completion for an alternate registry** | Unconditional no-op. `NpmRegistry::search` stays public-registry-only: `complete_package_names` is the top-level name-typing path, which has no per-dependency source to route on, so an alternate instance is never reached. **r3 (N-M3): that is now *enforced*, not merely true** — `search` returns an empty `Vec` when `tier == WorkspaceDeclared`, because the inherited method calls the ungated `HttpCache::get_cached` against `self.registry_base` (`registry.rs:468-478`) and would bypass S1's redirect-hop gating if a future call site ever did reach it. | Mirrors Cargo's own choice. Verdaccio/Artifactory `-/v1/search` compatibility is real but not universal; an allow-list or a runtime probe-and-cache layer is meaningfully more surface for a P3 item with no concrete request. Note the interaction with FR-017: `complete_package_names` is deliberately the *only* completion context left source-blind, and it is safe because the string being sent is a prefix the user typed into the name field, not a resolved private dependency name. | Static allow-list of known-compatible registry shapes — rejected, an opinionated compatibility table with no fixture backing. Runtime probe-and-cache-the-failure — rejected, new per-registry state and a first-request latency edge case for a completion-only feature. |
| **FR-012: `.npmrc` memoization shape** (S2 — redesigned) | `NpmConfigCache` is keyed by **`.npmrc` file path**, exactly like `deps-cargo`'s `ConfigFileCache` (`deps-cargo/src/config.rs:645-712`). It caches **raw, unvalidated** key→value entries and their mtime; the ancestor walk, tier merge, `${VAR}` expansion, `NpmRegistryIndex::new` validation and `classify_host` gating all re-run **per parse** against those cached entries. There is no workspace-root concept anywhere in this design. | Caching raw entries rather than resolved indexes is what makes a `didChangeConfiguration` policy change, or an env-var change, take effect immediately with no cache invalidation of its own — the same reason Cargo's cache stores raw tables. Keying by file path means N `package.json` files under one `.npmrc` collapse to one cached entry naturally, and "no ancestor `.npmrc`" is just an empty walk result needing no special case. Same `MAX_CONFIG_FILES = 256` cap and same `!=`-not-`>` mtime comparison (a `git checkout` moving mtime backwards must still invalidate). | (a) r1's per-workspace-root cache — rejected: `NpmParseResult::workspace_root()` returns `None` (`deps-npm/src/parser.rs:69`), so npm has no workspace root to key on, and inventing one would mean a second ancestor walk with its own definition of "root". (b) Caching the fully-resolved `NpmConfig` — rejected, it would have to be invalidated on every policy or environment change, which is exactly the bug class Cargo's raw-table caching avoids. |
| **FR-014: `~/.npmrc` home-directory resolution** | Unchanged from r1: add `dirs` v6 (`dirs::home_dir()`), per explicit user sign-off (spec §8 "Ask First"). | User-tier `.npmrc` is npm's dominant real-world private-registry mechanism, far more than Cargo's `$CARGO_HOME` override. A raw-`$HOME`-only strategy would miss `~/.npmrc` wherever `$HOME` is unset but the OS home directory still resolves (minimal containers, some CI runners). The critic's non-findings section independently confirmed `dirs` v6 is license-clean (MIT OR Apache-2.0; transitive `option-ext` is MPL-2.0, already in `deny.toml`'s allow list). | Raw `$HOME`/`%USERPROFILE%` only, no new dependency — the Cargo precedent; the user chose `dirs` for closer fidelity to npm's own `os.homedir()`. |
| **NFR-002: `NpmRegistryIndex` instead of promoting `RegistryIndex`** | Unchanged from r1: a new, minimal `deps-npm`-local newtype — https-only, no userinfo, `classify_host`/`RegistryAccessPolicy`-gated, **plus trailing-slash normalization** (S5) — with no trust-tier concept. | `deps-cargo`'s `RegistryIndex` is structurally coupled to `IndexTrust`, which exists solely to gate credential attachment. npm phase 1 attaches no credential at all, so promoting the type now means either stripping `IndexTrust` from a design that leans on it for Cargo's credential-provenance guarantee, or making `deps-npm` fabricate a trust value it never reads. Revisit at the follow-up auth-wiring spec — that is the two-real-consumers moment. | Promote `RegistryIndex` to `deps-core` now with `IndexTrust` made optional — rejected as premature abstraction, and it would force re-review of Cargo's already-shipped security surface outside this spec's file scope (spec §8 "Ask First"). |
| **Alternate fetches use the workspace-gated transport** (S1) | An alternate `NpmRegistry` instance carries `tier: NpmRegistryTier::WorkspaceDeclared` and fetches through `HttpCache::get_cached_workspace_with_headers` (**new**, see A1 below), never `get_cached_with_headers`. The public instance keeps `tier: Public` and today's call unchanged. | Mirrors `deps-cargo/src/sparse.rs:375-376`, where a `WorkspaceDeclared` index goes to `get_cached_workspace`. Parse-time `classify_host` validation alone gates only the *first* URL; the workspace transport is what re-classifies each **redirect hop**, which is FR-008's actual promise — a permitted public host 302-ing to `169.254.169.254` is otherwise unguarded. The r1 plan never stated this. | Validate once at parse time and use the ordinary transport — rejected, that is the redirect-hop hole `get_cached_workspace` exists to close. |
| **Freshness/publish-times for alternate-sourced dependencies** (A2 — new) | Phase 1 **skips** the full-packument publish-times fetch entirely when `tier == WorkspaceDeclared`: `publish_times()` returns an empty map for an alternate client. Relative-age suffixes are absent for private-registry dependencies; version data itself is unaffected. | `fetch_publish_times` uses `HttpCache::get_transport_only_with_headers` (`deps-npm/src/registry.rs:336`), and `HttpCache` has **no** workspace-gated `get_transport_only_*` variant — confirmed by enumerating `cache.rs`'s public fetch methods. Routing an alternate's multi-MB full packument through the ungated transport would reintroduce exactly the redirect hole S1 closes, for a cosmetic suffix. `fetch_publish_times` is already documented as degrading to an empty map on any failure, so this is an existing, already-handled shape — not a new error path. | Add `get_transport_only_workspace_with_headers` in this PR — rejected for phase 1: a second new `HttpCache` method with its own redirect/response-size review, to restore a cosmetic hint. Noted as the natural follow-up. |

## 2. Project Structure

```
crates/deps-npm/
├── src/
│   ├── config.rs             # NEW: .npmrc discovery (ancestor walk + ~/.npmrc),
│   │                         #   INI-grammar parsing, tier merge, ${VAR} expansion,
│   │                         #   NpmConfig, NpmRegistryIndex, NpmConfigCache,
│   │                         #   NpmRegistryIndexError
│   ├── parser.rs             # MODIFIED: parse_package_json_with_context(); each
│   │                         #   dependency's source set via NpmConfig::resolve_source_for
│   │                         #   (scope entry > top-level override, FR-004 > FR-003);
│   │                         #   NpmParseResult gains resolved_registries: Vec<NpmRegistryIndex>
│   ├── registry.rs           # MODIFIED: NpmRegistry gains tier: NpmRegistryTier and
│   │                         #   alternates: Arc<DashMap<String, Arc<NpmRegistry>>>;
│   │                         #   with_base() production constructor; register_alternate();
│   │                         #   alternate_client(); get_versions_from /
│   │                         #   get_latest_matching_from overrides
│   ├── ecosystem.rs          # MODIFIED: NpmParseContext threaded through
│   │                         #   NpmEcosystem::with_context; parse_manifest registers
│   │                         #   resolved_registries; CompletionSource +
│   │                         #   resolve_completion_source; complete_versions gains
│   │                         #   parse_result (FR-017)
│   ├── formatter.rs          # MODIFIED: can_resolve_source override (FR-009);
│   │                         #   suppress_package_url override (FR-015)
│   └── lib.rs                # MODIFIED: pub mod config; re-export NpmConfig,
│                             #   NpmRegistryIndex, NpmParseContext
crates/deps-core/
└── src/cache.rs              # MODIFIED (A1): add HttpCache::get_cached_workspace_with_headers
                              #   — get_cached_workspace's headered form, needed for npm's
                              #   abbreviated-packument Accept header. Inherent method on a
                              #   struct, NOT a trait-surface widening (spec §8 "Never" is
                              #   about the Registry/EcosystemFormatter traits).
                              #   Its rustdoc MUST carry the N-M1 credential warning — see below.
crates/deps-lsp/
├── src/config.rs             # MODIFIED: delete deps_lsp::config::CargoConfig (the one-field
│                             #   type at :636 — NOT deps_cargo::config::CargoConfig, an
│                             #   unrelated public type at deps-cargo/src/config.rs:358
│                             #   re-exported from deps-cargo/src/lib.rs:33, which this PR
│                             #   does not touch); add RegistriesConfig with
│                             #   workspace_registries: WorkspaceRegistriesSetting;
│                             #   DepsConfig.cargo -> DepsConfig.registries (:51).
│                             #   Also edit: the rustdoc example at :630-632 (it names
│                             #   CargoConfig and asserts its default) and the three test
│                             #   sites at :747, :769-770, :773 (test_default_config and
│                             #   test_cargo_config_section_deserialization, the latter's
│                             #   JSON literal `{"cargo": {...}}` included)
├── src/server.rs             # MODIFIED (S3): both set_registry_policy call sites,
│                             #   :391 (initialize) and :523 (didChangeConfiguration),
│                             #   read config.registries.workspace_registries
└── src/lib.rs                # MODIFIED (S3): register_ecosystems must Arc::clone the
                              #   policy for npm (today it is *moved* into
                              #   CargoParseContext at :253-286), and BOTH npm branches
                              #   — #[cfg(all(feature="npm", feature="deno"))] and
                              #   #[cfg(all(feature="npm", not(feature="deno")))] — must
                              #   construct NpmEcosystem::with_context. The latter uses the
                              #   register! macro today (:28, NpmEcosystem::new(cache)),
                              #   which would silently give npm a default, disconnected
                              #   policy in that feature combination; npm must be removed
                              #   from the macro path and written out explicitly.
Cargo.toml                    # MODIFIED: add `dirs = "6"` to [workspace.dependencies]
crates/deps-npm/Cargo.toml    # MODIFIED: dirs dependency
.github/workflows/            # MODIFIED (M5): SC-003's grep gate, scoped to non-test
                              #   sources only — see §7
```

**A1 doc requirement (N-M1).** `get_cached_workspace_with_headers`'s rustdoc must
carry the same credential warning `deps-core` already documents on its sibling
`get_cached_trusted_origin_with_headers` (`cache.rs:948-962`), stated in the
*opposite* direction: `extra_headers` are attached to the **initial request
only**, and the workspace transport pins by **host class, not origin**, so a
cross-origin redirect hop to any other policy-permitted host is followed with
those headers re-sent by reqwest's default policy. This method therefore **must
never carry a credential** — `get_cached_trusted_origin_with_headers` is the
origin-pinned method for that. Harmless in phase 1, where the only header is
`Accept: application/vnd.npm.install-v1+json`, but directly load-bearing for the
auth-wiring follow-up this spec defers to, which is exactly when someone will
reach for the nearest `*_with_headers` method.

**Docs to update alongside** (per `.claude/rules/branching.md`): `CHANGELOG.md`
(**Breaking**: `cargo.workspace_registries` → `registries.workspace_registries`),
`ECOSYSTEM_GUIDE.md`, root `README.md`, and any editor-settings snippet naming
the old key.

**N-S2 — state the blast radius accurately.** `#[serde(deny_unknown_fields)]` is
on **`DepsConfig` itself** (`deps-lsp/src/config.rs:34`), not merely on the
section struct, so a client still sending `"cargo": {...}` fails the parse of the
**entire settings payload** — the user also loses `inlay_hints`, `diagnostics`,
`cache`, `cold_start`, `code_lens`, `freshness` and `network`, not just the
registry setting. What happens next depends on *when* the stale payload arrives,
and the two cases differ; the CHANGELOG/README wording must not describe only
the second:

- **At `initialize` (`server.rs:385-395`) — the common case, since most clients
  send settings exactly once.** There is no previous configuration to keep:
  `Backend::new` seeds `DepsConfig::default()` (`server.rs:79`), `parse_config`
  returns `None` (`server.rs:55-65`), the whole `if let` block is skipped, and
  the defaults stand. This is a **full reset to defaults**, announced only by a
  `tracing::warn!` most editors never surface. It fails *closed* for the
  security-relevant setting — `WorkspaceRegistriesSetting::default()` is
  `PublicOnly` and `HttpCache::new` already constructs with
  `RegistryAccessPolicy::default()` (`cache.rs:708-714`), so a skipped
  `set_registry_policy` leaves the policy at `PublicOnly` — but every other
  section silently reverts too.
- **At a later `workspace/didChangeConfiguration` (`server.rs:516-518`).** Here
  `parse_config` returning `None` early-returns and the previously applied live
  configuration *is* retained.

So the accurate one-line framing is: *"a client still sending
`cargo.workspace_registries` has its entire deps-lsp configuration rejected;
sent at `initialize` this means every setting falls back to its default (the
registry policy safely to `public_only`), and on a later configuration change the
previous settings are kept."* This blast radius does **not** reverse the C2
decision — a transitional `cargo` alias remains rejected on the pre-1.0
no-shims rule, and the failure is loud in the log and fails closed on the one
setting that matters for security — but it does mean the CHANGELOG entry and
`README`/`ECOSYSTEM_GUIDE` must say "all settings", not "this setting".

## 3. Data Model

```rust
// crates/deps-npm/src/config.rs

/// A validated, normalized npm registry index URL: https-only (see the scheme rule on
/// `new` for the one `cfg`-gated carve-out), no userinfo,
/// `classify_host`/`RegistryAccessPolicy`-gated. Deliberately has no trust-tier concept
/// (§1 NFR-002) — npm phase 1 attaches no credential to any request.
///
/// Normalization (S5): trailing `/` characters are stripped from the path before
/// storage, so `https://npm.pkg.github.com/` and `https://npm.pkg.github.com` are one
/// index, not two. `versions_url` builds `{base}/{name}`, so an unstripped trailing
/// slash would produce `https://npm.pkg.github.com//@myorg/pkg` — and the raw string
/// would key two entries in the router's `alternates` map for one registry.
/// `as_str()` is the single normalized form used on **both** sides of that map
/// (registration and lookup), exactly as `RegistryIndex::as_str` is for Cargo
/// (`deps-cargo/src/registry.rs:478-487`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NpmRegistryIndex {
    url: url::Url,
}

impl NpmRegistryIndex {
    /// Validates, normalizes and wraps `raw`. Every candidate is treated as
    /// workspace-declared for policy purposes — project-tier and user-tier `.npmrc`
    /// are gated identically, since npm phase 1 has no `$CARGO_HOME`-equivalent
    /// "trusted, never policy-checked" tier (auth is out of scope, and both tiers are
    /// equally capable of naming an internal host).
    ///
    /// Scheme rule (S6, corrected in r3 by N-C1): `https` is required
    /// **unconditionally**. The single carve-out is an `http` **loopback** host
    /// (`127.0.0.1`/`localhost`/`::1`), and the helper implementing it is
    /// `#[cfg(any(test, feature = "test-util"))]` — mirroring *both*
    /// `deps-cargo`'s `is_loopback_url` (`deps-cargo/src/config.rs:185`, whose own doc
    /// spells out this gating) and `deps-core`'s `is_loopback_host`/`ensure_https`
    /// (`deps-core/src/cache.rs:121,151-160`). A release build has no `http`
    /// exception at all.
    ///
    /// The gate is not merely conventional — it is the only reachable design.
    /// `HttpCache::ensure_https` guards all four send sites (`cache.rs:1158,1232,1294,1415`),
    /// two of which (`conditional_request_with_headers`, `fetch_and_store_with_headers`)
    /// are on `get_cached_workspace`'s own path. Accepting `http://localhost:4873` here in
    /// a release build would produce an `AlternateRegistry` that always fails at fetch
    /// time with an opaque `CacheError("URL must use HTTPS")` — strictly worse for the
    /// user than FR-006's fail-closed `CustomRegistry` plus a warning naming the raw
    /// value. Widening it for real would require changing `ensure_https`, a `deps-core`
    /// security enforcement point outside this spec's file scope and its §8 "Ask First"
    /// list.
    ///
    /// An `https` loopback host (`https://localhost:4873`) is accepted by validation in
    /// every build; its *reachability* is then decided by `RegistryAccessPolicy`, which
    /// denies `HostClass::Loopback` under the default `PublicOnly`.
    pub fn new(raw: &str, policy: &RegistryAccessPolicy) -> Result<Self, NpmRegistryIndexError>;

    /// The normalized index URL — the canonical key for the router's `alternates` map
    /// and for `DependencySource::AlternateRegistry { index }`.
    pub fn as_str(&self) -> &str;
}

/// The merged, resolved view of a workspace's `.npmrc` hierarchy (project tier
/// overrides user tier). Plain lookup table with one resolution method — mirrors
/// `deps-cargo`'s `CargoConfig`.
#[derive(Debug, Default)]
pub struct NpmConfig {
    /// Top-level `registry=` override (FR-003). `Err` carries the raw value as written,
    /// for the FR-006 `CustomRegistry` and the warning log.
    registry: Option<Result<NpmRegistryIndex, InvalidEntry>>,
    /// `@scope:registry=` entries (FR-004).
    ///
    /// **Key format (M6)**: the scope **including** its leading `@`, byte-exact as
    /// written in `.npmrc` (`"@myorg"`), with no case folding. Lookup uses the
    /// dependency's own `@scope/` name prefix, also byte-exact. This matches npm
    /// itself, whose config lookup is a literal `@${scope}:registry` string
    /// concatenation against byte-exact ini keys. Consequence worth documenting: a
    /// `.npmrc` line `@MyOrg:registry=...` does **not** apply to `@myorg/pkg`. npm
    /// lowercases *package names* at publish time, but it does not case-fold `.npmrc`
    /// keys, so folding here would make this LSP resolve a registry npm itself would
    /// not — a silent divergence in the exact direction FR-006 forbids.
    scoped_registries: HashMap<String, Result<NpmRegistryIndex, InvalidEntry>>,
}

/// A `registry=`/`@scope:registry=` entry that was present but unusable, carrying the
/// raw value as written so the parser can build `CustomRegistry { url }` and the
/// warning can name it.
#[derive(Debug, Clone)]
pub struct InvalidEntry {
    pub raw: String,
    pub reason: NpmRegistryIndexError,
}

impl NpmConfig {
    /// Resolves `package_name` straight to its final `DependencySource` (C1).
    ///
    /// - FR-004 > FR-003: a matching `@scope:registry=` entry wins outright over the
    ///   top-level `registry=` override.
    /// - FR-005: no matching entry -> `DependencySource::Registry` (public default).
    /// - FR-006/FR-007/FR-008: a matching entry that is present but invalid,
    ///   unexpandable or policy-blocked -> `DependencySource::CustomRegistry { url: raw }`
    ///   plus a `tracing::warn!` — never a silent fall back to `Registry`.
    ///
    /// There is deliberately no intermediate `RegistryResolution` enum: its three cases
    /// map total and information-preservingly onto three existing `DependencySource`
    /// variants, so it would exist only to be destructured one line later.
    pub fn resolve_source_for(&self, package_name: &PackageName) -> DependencySource;
}

/// Per-`.npmrc`-file memoization (FR-012, S2), keyed by **file path** — the same shape
/// as `deps-cargo::config::ConfigFileCache` (`deps-cargo/src/config.rs:645-712`).
/// There is no workspace-root key: npm has no workspace-root concept for config
/// discovery (`NpmParseResult::workspace_root()` returns `None`), and neither does
/// Cargo's config cache.
///
/// Caches **raw, unvalidated** entries plus the file's mtime. Expansion, validation and
/// policy gating all re-run per parse against these cached entries, so a
/// `didChangeConfiguration` policy change or an environment change takes effect
/// immediately with no invalidation of its own — the same reason Cargo caches raw
/// tables. mtime is compared with `!=`, not `>` (a `git checkout` to an older file must
/// still invalidate). Capacity `MAX_NPMRC_FILES = 256`, mirroring `MAX_CONFIG_FILES`.
#[derive(Debug, Default)]
pub struct NpmConfigCache {
    files: dashmap::DashMap<PathBuf, Arc<ParsedNpmrc>>,
}

/// Owned by `NpmEcosystem`, shared across every document it parses — the npm analogue of
/// `deps_cargo::parser::CargoParseContext` (S3: the r1 plan's config-cache-only context
/// was missing the policy its own `NpmRegistryIndex::new` requires).
#[derive(Debug, Clone, Default)]
pub struct NpmParseContext {
    pub policy: Arc<RegistryAccessPolicy>,
    pub config_cache: Arc<NpmConfigCache>,
}

// crates/deps-npm/src/registry.rs

/// Which transport an `NpmRegistry` instance fetches through (S1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmRegistryTier {
    /// `registry.npmjs.org` (or a test override) — `HttpCache::get_cached_with_headers`,
    /// today's path, unchanged.
    Public,
    /// A `.npmrc`-declared alternate index — `HttpCache::get_cached_workspace_with_headers`,
    /// so every redirect hop is re-classified (mirrors `deps-cargo/src/sparse.rs:375-376`).
    WorkspaceDeclared,
}
```

### `NpmRegistry` extension (M1, M2)

No `AlternateNpmClient` type is invented. `NpmRegistry` already carries
`registry_base: String` and a private `build(cache, base)` (`registry.rs:177-193`),
so an alternate client **is** an `NpmRegistry` with a different base and
`tier: WorkspaceDeclared`:

- **M1**: `with_registry_base` is `#[cfg(any(test, feature = "test-util"))]`
  (`registry.rs:206`), so it cannot be the production path. Add
  `pub fn with_base(cache: Arc<HttpCache>, index: &NpmRegistryIndex) -> Self`,
  ungated, taking a validated `NpmRegistryIndex` (not a bare `String`) so the
  type system carries the validation, and setting `tier: WorkspaceDeclared`.
  `with_registry_base` stays as-is for mockito.
- **M2**: `alternates: Arc<DashMap<String, Arc<NpmRegistry>>>`, **not** a bare
  `DashMap`. `NpmRegistry` is `#[derive(Clone)]` and `deps-lsp/src/lib.rs:281`
  hands a *clone* to `DenoEcosystem::with_npm`; a bare field would silently fork
  the map, so npm and Deno would each see only their own registrations.
  `publish_times` is already `Arc<DashMap>` for exactly this reason.
- Each alternate instance gets its **own** `publish_times` map. This is a
  correctness requirement, not just tidiness: that map is keyed by bare package
  name, so sharing one map across registries would let a public `@myorg/x`'s
  publish times satisfy a lookup for a private `@myorg/x`. Per-instance maps make
  the collision structurally impossible. (In phase 1 an alternate's map stays
  empty anyway, per the A2 decision.)
- Invariants to document in code:
  - Only the root (`Public`) instance ever registers alternates; an alternate's
    own `alternates` map is always empty. `with_base` therefore never populates it.
  - **An alternate never performs a package-*name* search (N-M3).** `NpmRegistry`
    inherits `search` (`registry.rs:468-478`), which calls the **ungated**
    `HttpCache::get_cached` against `self.registry_base`. On an alternate
    instance that would send a query to a workspace-declared host through the
    baseline transport, bypassing the S1 redirect-hop gating entirely. Today's
    routing never reaches it (`complete_package_names` uses the root instance,
    §1 FR-011), but nothing *enforces* that. Enforce it: `search` returns
    `Ok(Vec::new())` immediately when `tier == WorkspaceDeclared`, with a
    `debug_assert!` and a comment naming this invariant. This is cheaper and
    more robust than relying on the call graph — cf. the project's own
    "a gate before a match proves coverage of that function only" lesson.
- `register_alternate(&self, index: NpmRegistryIndex)` is idempotent and capped at
  `MAX_ALTERNATE_REGISTRIES = 256` with a `tracing::warn!` at capacity, mirroring
  `deps-cargo/src/registry.rs:429-465`. Called from
  `NpmEcosystem::parse_manifest` over `NpmParseResult::resolved_registries`,
  mirroring `deps-cargo/src/ecosystem.rs:245-247` — the one point where a
  per-document `.npmrc` resolution and the long-lived shared router meet.
- `alternate_client(&self, index: &str) -> Option<Arc<NpmRegistry>>` — plain map
  lookup, no validation, no registration, keyed by the same normalized
  `NpmRegistryIndex::as_str()` on both sides (`deps-cargo/src/registry.rs:487`).

#### `get_versions_from` / `get_latest_matching_from` dispatch (N-S1)

Both overrides must enumerate the same three arms, and **both must be asserted
independently in tests** — Cargo's own comment at
`deps-cargo/src/registry.rs:529-532` records that this enumeration "has been
wrong twice during design review":

| `source` | Arm | Rationale |
|---|---|---|
| `AlternateRegistry { index }`, `alternate_client(index)` is `Some(c)` | Fetch via `c` | The resolved private index |
| `AlternateRegistry { index }`, `alternate_client(index)` is `None` | `Err(DepsError::PackageNotFound { registry: "alternate registry (not registered)" })` | **Never** the public client |
| every other variant (`Registry`, `CustomRegistry`, ...) | Today's public-registry path | `CustomRegistry` is already gated out upstream by `can_resolve_source`; this arm is the unchanged status quo |

Two points that distinguish npm from Cargo here:

- Cargo has a **fourth** arm — `None if *mirrors_crates_io` degrades to crates.io
  (`registry.rs:503,529`) — justified because Cargo verifies per-version checksum
  equality against crates.io for a declared mirror. npm sets
  `mirrors_crates_io: false` unconditionally and has no equivalent
  mirror-verification concept, so that arm is **dead for npm and must not be
  written**. The tempting simplification — "npm has no mirrors, so an
  unregistered index just falls back to the public client" — is precisely the
  FR-006/#248 leak: it would send a private package name to
  `registry.npmjs.org`. This is why the `None` arm is unconditionally the error.
- **No lazy creation on the fetch path.** Registration stays parse-time-only, in
  `NpmEcosystem::parse_manifest` over `resolved_registries`, mirroring
  `deps-cargo/src/ecosystem.rs:248` — the *only* `register_alternate` call site
  in the workspace. Creating a client lazily from `get_versions_from` is not
  merely un-precedented, it is not constructible there: the fetch path holds only
  the already-validated `index: String` from `DependencySource`, while
  `with_base` requires an `NpmRegistryIndex`, whose construction requires the
  `RegistryAccessPolicy` — the exact coupling `alternate_client`'s doc
  (`deps-cargo/src/registry.rs:475-480`) deliberately avoids re-introducing at
  lookup time. Keeping registration in one place also keeps `alternates`'
  concurrency story unchanged: `DashMap::entry` is taken only from
  `register_alternate` (which reads `len()` *before* `entry()` to avoid the
  self-deadlock its Cargo counterpart documents at `registry.rs:430-432`), while
  every fetch-path access is a read-only `get`.

The reachable shapes for the `None` arm are the same two Cargo has: the
`MAX_ALTERNATE_REGISTRIES = 256` cap silently declining a new index, and a fetch
racing registration (a background fetch for a document whose `parse_manifest` has
not completed). Both must degrade to `PackageNotFound`, not to a public fetch.

### Entity summary

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `DependencySource::Registry` | Existing variant, unchanged | Public registry — FR-005's fallback and today's universal behavior |
| `DependencySource::AlternateRegistry` | Existing `deps-core` variant (#440), reused as-is | `index: String` (the **normalized** `NpmRegistryIndex::as_str()`), `mirrors_crates_io: false` always |
| `DependencySource::CustomRegistry` | Existing `deps-core` variant, reused as npm's FR-006 fail-closed state (C1) | `url: String` — the raw `.npmrc` value as written; `is_version_resolvable() == false` |
| `NpmConfig` | New `deps-npm` type — merged resolved `.npmrc` hierarchy | `registry: Option<Result<NpmRegistryIndex, InvalidEntry>>`, `scoped_registries: HashMap<String, Result<..>>` keyed by `@scope` byte-exact |
| `InvalidEntry` | New — a present-but-unusable entry | `raw: String`, `reason: NpmRegistryIndexError` |
| `NpmRegistryIndex` | New minimal `deps-npm`-local newtype (NFR-002) | https-only (`http`-loopback carve-out is `cfg(test)`/`test-util`-only), no userinfo, policy-gated, trailing-slash-normalized, no trust tier |
| `NpmConfigCache` | New — per-`.npmrc`-file memoization (FR-012) | Keyed by file path, caches raw entries + mtime, `!=` comparison, cap 256 |
| `NpmParseContext` | New — the per-ecosystem shared context | `policy: Arc<RegistryAccessPolicy>`, `config_cache: Arc<NpmConfigCache>` |
| `NpmRegistryTier` | New private enum — transport selection (S1) | `Public` / `WorkspaceDeclared` |
| `NpmRegistry` (extended) | Existing `deps-npm` `Registry` impl, now also the router | `+ tier`, `+ alternates: Arc<DashMap<String, Arc<NpmRegistry>>>` (cap 256), `+ with_base`/`register_alternate`/`alternate_client` |
| `CompletionSource` + `resolve_completion_source` | New private items in `deps-npm/src/ecosystem.rs` (FR-017) | `NotInManifest` / `Resolved(DependencySource)` / `Ambiguous` |
| `HttpCache::get_cached_workspace_with_headers` | New inherent method on `deps-core`'s `HttpCache` (A1) | Headered form of `get_cached_workspace`; no trait change |
| `Registry::get_versions_from` / `get_latest_matching_from` | Existing defaulted `deps-core::Registry` trait methods | Overridden by `NpmRegistry`, no signature change |
| `EcosystemFormatter::can_resolve_source` / `suppress_package_url` | Existing defaulted `deps-core` trait methods (`lsp_helpers/mod.rs:1449,1531`) | Overridden by `NpmFormatter`, no signature change |

`EcosystemFormatter::source_is_public_registry_content` is deliberately **not**
overridden (M3): its default is `matches!(source, DependencySource::Registry)`,
which is already correct for npm — an alternate registry's content is not
npmjs.org's, and npm has no `mirrors_crates_io` equivalent to except. Documented
side effect: a dependency resolved to an alternate registry drops out of OSV
vulnerability scanning and out of public-registry hover links. That is the
desired behavior (advisories keyed to a public package name do not apply to a
same-named private package), but it is a real behavior change and belongs in
`ECOSYSTEM_GUIDE.md` rather than being left implicit.

## 4. API Design

No new LSP-facing endpoint. One **breaking** configuration change:
`cargo.workspace_registries` → `registries.workspace_registries` (§1 C2
decision), observed identically at `initialize`
(`deps-lsp/src/server.rs:391`) and `workspace/didChangeConfiguration`
(`:523`), both feeding the same `HttpCache::set_registry_policy`.
`WorkspaceRegistriesSetting` and its `to_policy()` are reused verbatim — the
critic independently confirmed they are already generic with no Cargo-specific
fields (`deps-lsp/src/config.rs:667,697`).

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| Alternate npm registry (Verdaccio/Artifactory/GitHub Packages npm/Azure Artifacts) | outbound | HTTPS, npm packument JSON (abbreviated) | Unauthenticated in phase 1. Every request goes through `HttpCache::get_cached_workspace_with_headers`, so `classify_host`/`RegistryAccessPolicy` gates the initial URL **and** every redirect hop (S1). Reached only via a client registered at parse time; an `AlternateRegistry` index with no registered client produces **no outbound request at all** — `PackageNotFound`, never a public-registry retry (N-S1, §3) |
| `.npmrc` project tier | filesystem read | INI-like text | Ancestor walk from the `package.json` directory, capped at 64 ancestors (matching `deps-cargo`'s `MAX_CONFIG_ANCESTOR_DEPTH`). Collected closest-first; a closer file's key wins. New walk — `deps-npm` has none today, and Cargo's `discover_workspace` is not reusable across crates |
| `.npmrc` user tier | filesystem read | INI-like text | `dirs::home_dir().join(".npmrc")` (FR-014) |
| Process environment | read | `${VAR}` expansion | Only for `registry=`/`@scope:registry=` values (§1 S4 decision). Never for any auth-shaped key, which is not parsed at all |

**M9 — `$HOME` collision and dedupe.** Two things the r1 plan left unstated:

1. FR-002's ancestor walk is a deliberate divergence from npm itself, which
   reads only the project-root `.npmrc` (plus user and global tiers), not every
   ancestor directory. The walk is chosen for monorepo ergonomics — a package
   under `packages/foo/` picking up the repo-root `.npmrc` — and matches Cargo's
   own `.cargo/config.toml` discovery. It must be documented in
   `ECOSYSTEM_GUIDE.md` as an intentional superset of npm's behavior.
2. A project living under `$HOME` has `$HOME` as an ancestor, so the project-tier
   walk finds `~/.npmrc` — the *same file* as the user tier. Uncompared, it would
   be counted as a project-tier entry and win outright over itself, which is
   harmless for precedence but double-reads and double-counts the file, and
   becomes wrong the moment the two tiers stop being policy-symmetric. Dedupe by
   **canonicalized** path (not string equality, so a symlinked home is caught
   too), exactly as `deps-cargo`'s `load_tiers` does
   (`deps-cargo/src/config.rs` `load_tiers`, the `cargo_home_canonical` filter):
   the user-tier path is canonicalized once and filtered out of the project-tier
   list.

## 6. Security

- **NFR-001 / FR-013** (no auth-shaped key ever parsed): the `.npmrc` parser in
  `config.rs` recognizes exactly two key shapes — `registry` and
  `@<scope>:registry` — and *ignores every other line* rather than
  parsing-then-discarding it. There is no `HashMap<String, String>` of
  "everything else" anywhere in `NpmConfig` for an
  `_authToken`/`_auth`/`_password`/`_authIdent`/`always-auth`/`//host/:_*` value
  to land in even accidentally. This is a structural guarantee (no code path can
  produce such a value), not a runtime filter. Verified by the NFR-001 structural
  test plus the §7 CI grep gate.
- **`${VAR}` expansion is auth-free by construction** (S4): expansion runs
  *inside* `NpmRegistryIndex::new`'s candidate path, reached only from the two
  recognized key shapes. An auth-shaped key is never parsed, so its `${VAR}` is
  never expanded, never held, never logged. Expansion widens what a *registry
  URL* can be — it does not widen which keys are read. The expanded value is
  untrusted input subject to the full https/no-userinfo/`classify_host` gate, so
  the environment can only select among URLs the policy already permits.
  Logging rule: a `tracing::warn!` about an invalid entry logs the **raw**
  (unexpanded) value, so an expanded-but-rejected URL cannot leak an environment
  variable's contents into the log.
- **NFR-002** (URL validation): every `NpmRegistryIndex::new` call requires
  `https` unconditionally, rejects userinfo, normalizes the trailing slash, and
  consults `classify_host`/`RegistryAccessPolicy` before a candidate can become
  fetchable. The single `http` carve-out is a loopback host under
  `#[cfg(any(test, feature = "test-util"))]`, mirroring `deps-cargo`'s
  `is_loopback_url` (`config.rs:185`) and `deps-core`'s
  `is_loopback_host`/`ensure_https` (`cache.rs:121,151-160`). **A release build
  has no `http` exception** — and could not usefully have one, since
  `ensure_https` guards every send site on the `get_cached_workspace` path
  (`cache.rs:1158,1232`), so a release-accepted `http://localhost` index would
  only ever surface as an opaque `CacheError` instead of FR-006's fail-closed
  `CustomRegistry` + warning (N-C1).
- **FR-008 redirect-hop gating** (S1): validation at parse time bounds only the
  first URL. Every alternate fetch goes through the workspace transport
  (`get_cached_workspace_with_headers`), which re-classifies each redirect hop —
  without it, an allowed public host redirecting to `169.254.169.254` would be
  followed. The `cache.rs` tests at `:1908,1955` are the existing evidence that
  this transport is what closes the hole.
- **A2**: the full-packument freshness fetch has **no** workspace-gated
  transport available, so it is skipped for alternate-sourced dependencies
  rather than routed through the ungated one.
- **NFR-003** (residual SSRF-adjacent reachability): stated explicitly, identical
  in shape to Cargo's NFR-003 — even with NFR-001/002 satisfied, an
  unauthenticated HTTPS GET to a workspace-declared (or user-declared) index
  still occurs, usable for existence-probing by a hostile repository. Mitigated
  identically by the shared `registries.workspace_registries` defaulting to
  `public_only`. **Two divergences from Cargo needing security-reviewer
  sign-off**: (a) npm's user-tier `~/.npmrc` is gated by the *same* policy as the
  project tier, where Cargo treats `$CARGO_HOME` as trusted-by-definition — npm's
  tiers are policy-symmetric because phase 1 has no credential provenance to
  protect; (b) the policy is now shared across **all** ecosystems (§1 C2), so a
  user setting it to `all` for npm also widens it for Cargo. (b) is the honest
  consequence of one global `HttpCache` policy and is the reason the key is being
  renamed out of the `cargo.*` namespace rather than duplicated.

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|---------------|-------------------|
| Unit | `cargo nextest` | `.npmrc` INI grammar: `#`/`;` comments, blank lines, `key=value` and `key = value`, a line with no `=` skipped with a warn while other lines still apply | FR-001, spec §6 rows |
| Unit | `cargo nextest` | Precedence, both axes independently: `@scope:registry` over top-level `registry` (FR-004/NFR-006); project tier over user tier (FR-002) | FR-003/FR-004/NFR-006 |
| Unit | `cargo nextest` | **FR-003 end-to-end**: a top-level `registry=` override rewrites *every unscoped* dependency's source to `AlternateRegistry`, and leaves a scoped dependency with its own `@scope:registry` entry alone (M7) | FR-003, US-002 |
| Unit | `cargo nextest` | FR-006 fail-closed: an invalid `@scope:registry=` yields `CustomRegistry { url: <raw> }`, `is_version_resolvable() == false`, and no public-registry fetch for that scope — the npm form of the #248 regression test | SC-004, US-004 |
| Unit | `cargo nextest` | FR-007: `${UNDEFINED_VAR}` yields `CustomRegistry`, never a literal-placeholder fetch. **And its complement (S4)**: `${DEFINED_VAR}` expands and then validates, with a defined-but-invalid expansion (e.g. `http://`) still failing closed | FR-007, S4 decision |
| Unit | `cargo nextest` | **FR-008 policy matrix (M7)**: the same loopback/RFC1918 index resolves under `all`, is blocked (→ `CustomRegistry`) under `public_only`, and every workspace-declared index is blocked under `off`. Use an **`https`** loopback URL for the policy-matrix rows, so the row exercises the *policy* gate and not the scheme gate | FR-008 |
| Unit | `cargo nextest` | **N-C1 scheme gate**: `http://localhost:4873` is accepted by `NpmRegistryIndex::new` only because the test binary enables the `cfg(test)`/`test-util` carve-out; assert that a **non**-loopback `http://` host (`http://registry.example.com`, and the near-miss `http://localhost.evil.com`) is rejected even under that cfg, mirroring `cache.rs:1600-1608`'s existing near-miss assertions. There is no release-build assertion to write — the carve-out is compiled out — so the invariant is carried by the `#[cfg]` attribute plus this near-miss test | FR-006, NFR-002 |
| Unit | `cargo nextest` | **FR-009 (M7)**: `NpmFormatter::can_resolve_source` is `true` for `AlternateRegistry`, `false` for `CustomRegistry` and `Registry`'s non-resolvable siblings; `source_is_public_registry_content` keeps its default `false` for `AlternateRegistry` | FR-009, M3 |
| Unit | `cargo nextest` | **FR-015 (M7)**: `suppress_package_url` returns `true` for `AlternateRegistry`/`CustomRegistry`, `false` for `Registry` — no npmjs.com link on a private-package hover | FR-015 |
| Unit | `cargo nextest` | **FR-017 (C3)**: `resolve_completion_source` returns `NotInManifest` / `Resolved` / `Ambiguous` correctly; `complete_versions` offers nothing for `Ambiguous`, for `CustomRegistry`, and for an `AlternateRegistry` whose index is unregistered; routes to the alternate client when registered | FR-017 |
| Unit | `cargo nextest` | NFR-001 structural test: no field or variant in `deps-npm`'s config types can hold an auth-shaped value; a fixture `.npmrc` containing `_authToken`/`_auth`/`//host/:_password` parses to a config with those lines absent entirely | SC-003 |
| Unit | `cargo nextest` | FR-012/NFR-004: `NpmConfigCache` — one read per `.npmrc` file path, mtime-invalidated with `!=` (an mtime moved *backwards* still invalidates); adapt `deps-cargo/src/config.rs`'s `fs_probe` stat/read-counting pattern | NFR-004 |
| Unit | `cargo nextest` | M9: a `.npmrc` reachable as both an ancestor and the user tier is read once (canonicalized-path dedupe), including through a symlinked home | M9 |
| Unit | `cargo nextest` | S5: `https://x/` and `https://x` normalize to one `NpmRegistryIndex`, register one `alternates` entry, and build `{base}/@scope/pkg` with no doubled slash | S5 |
| Unit | `cargo nextest` | M6: `@MyOrg:registry=` does not apply to `@myorg/pkg` (byte-exact scope keys, no case folding) | M6 |
| Integration | `mockito` | `NpmRegistry::get_versions_from` routes an `AlternateRegistry`-sourced dependency to the mocked index and never to `registry.npmjs.org`. **The test must set the policy to `WorkspaceRegistryAccess::All`** (S6, reason corrected in r3): mockito binds `http://127.0.0.1`, so the test depends on *two* gates being open — the `cfg(test)`/`test-util` `http`-loopback carve-out in `NpmRegistryIndex::new` (which a test binary enables automatically; an integration test under `tests/` needs `deps-npm`'s `test-util` feature, exactly as `deps-cargo`'s alternate-registry tests do) **and** the runtime policy, since `classify_host` returns `HostClass::Loopback` and the default `PublicOnly` denies it. Under the default the test would fail for the wrong reason | US-001/US-002 |
| Integration | `mockito` | The alternate client's requests go through the workspace transport: a mocked index that 302s to a private-range host is not followed (S1) | FR-008 |
| Integration | `mockito` | **N-S1 fetch-path fail-closed**: `get_versions_from` **and** `get_latest_matching_from`, each asserted independently, return `PackageNotFound` for an `AlternateRegistry` whose index was never registered — with a `registry.npmjs.org`-shaped mock in place asserting **zero** hits, so a silent public fallback fails the test rather than passing it. Cargo's own comment (`deps-cargo/src/registry.rs:529-532`) records that this exact arm enumeration "has been wrong twice during design review", which is why both sites get their own assertion | FR-010 |
| Unit | `cargo nextest` | **N-M3**: `NpmRegistry::search` on an instance with `tier == WorkspaceDeclared` returns an empty `Vec` and issues no request — the enforcement of §3's "an alternate never performs a name search" invariant | FR-011 |
| CI gate | `.github/workflows` (M5) | SC-003's grep for `_authToken`/`_auth`/`_password`/`_authIdent` **restricted to non-test sources** — the NFR-001 fixtures deliberately *contain* those strings to prove they are skipped, so a naive repo-wide grep fails on its own evidence. Scope: `crates/deps-npm/src/**` excluding `#[cfg(test)]` modules and `crates/deps-npm/tests/**`. Simplest workable rule: grep only files under `crates/deps-npm/src/` and exclude any line inside a `mod tests` block; if that proves brittle, move the fixtures to `crates/deps-npm/tests/fixtures/` and exclude that directory wholesale | SC-003 |
| Live (Registry Integration Gate) | manual, before filing the PR | Real or mocked Verdaccio: scoped-registry hover, diagnostics **and completion** end-to-end | SC-001 |

**M4 — SC-002 cannot hold literally.** `NpmEcosystem::complete_versions` gains a
`parse_result` parameter (FR-017), and `deps-npm/src/ecosystem.rs` has ~10
existing tests calling it directly (`:295,312,328,379,628,645,661,677,...`).
Every one needs an added argument. Cargo's equivalent change forced exactly this,
introducing an `empty_parse_result()` helper
(`deps-cargo/src/ecosystem.rs:374-377`) that returns `NotInManifest` for any name
and so preserves each test's original behavior. `deps-npm` does the same. Spec
SC-002 is being reworded from "passes unmodified" to a behavioral claim
(unchanged *results*, with a mechanical signature-only fixture change) — see the
spec revision.

## 8. Performance Considerations

- One `.npmrc` **read** per distinct file per mtime change; one ancestor walk and
  one merge/validate pass per `parse_manifest` call. The walk's `stat` calls are
  unavoidable and paid every parse — the same cost class as Cargo's
  `ConfigFileCache::get_or_parse` mtime check — but file *content* is read only
  on a miss.
- NFR-004's "zero additional filesystem reads" holds for content, not for
  `stat`s: a workspace with no `.npmrc` at any tier pays at most one `stat` per
  ancestor directory (capped at 64) plus one for `~/.npmrc`, and reads nothing.
  The spec's NFR-004 wording is being corrected to say so.
- Validation and policy gating re-run per parse by design (§1 FR-012) — they are
  pure CPU over a handful of short strings, and re-running them is what makes a
  policy or environment change take effect without invalidation.
- `dirs::home_dir()` is a single cheap OS call, not a filesystem walk.
- Alternate-sourced dependencies skip the multi-MB full-packument freshness fetch
  (A2), so they are strictly *cheaper* than public ones, not more expensive.

## 9. Rollout Plan

Single PR, no phased rollout. Behavior for a workspace with no `.npmrc` is
unchanged (NFR-005), and `registries.workspace_registries` still defaults to
`public_only`.

The one non-additive change is the **config key rename** (§1 C2): a client whose
settings still say `cargo.workspace_registries` fails `DepsConfig`'s
`deny_unknown_fields` parse — and since that attribute sits on `DepsConfig`
itself, the rejection takes the **whole settings payload** with it, not just the
registry section (N-S2). Sent at `initialize` that means every setting falls back
to its default (the registry policy safely to `public_only`, since
`HttpCache::new` already starts there); sent later via
`didChangeConfiguration` it means the previously applied settings are kept. The
failure is logged, but only as a `tracing::warn!` most editors do not surface, so
it is diagnosable rather than visible. It must appear in `CHANGELOG.md` under a
**Breaking** heading — worded per §2's N-S2 framing, covering *both* cases and
saying "all settings", not "this setting" — and in
`README.md`/`ECOSYSTEM_GUIDE.md`'s settings tables. Pre-1.0, so no deprecation
window (project CLAUDE.md).

## 10. Constitution Compliance

No `constitution.md` exists yet — cross-checked against `.claude/rules/*.md`:

| Rule source | Status | Notes |
|-------------|--------|-------|
| `rust-code.md` — `unsafe_code = "forbid"`, `thiserror`, native async traits | Compliant | `NpmRegistryIndexError` via `thiserror`; no `unsafe`; `get_versions_from` is already a native async trait method |
| `rust-code.md` — registry crates use `reqwest`+`rustls`, no hand-rolled version comparison | Compliant | Reuses `HttpCache`/`node_semver`; no new HTTP client |
| `testing.md` — `cargo nextest`, `mockito`, `tempfile` | Compliant | §7 follows this |
| `continuous-improvement.md` — Registry Integration Gate | Planned | Live row in §7, required before filing the PR |
| User CLAUDE.md — check versions via context7 before adding a dependency | Documented deviation | context7 MCP unavailable in this session (matches existing project memory); `dirs` v6 verified via crates.io/docs.rs and independently license-checked by the critic against `deny.toml`. Re-confirm at implementation time |
| User CLAUDE.md — MVP, no premature abstraction | Compliant | This revision *removes* two invented types (`RegistryResolution`, `AlternateNpmClient`) in favor of existing ones; NFR-002 still declines to promote `RegistryIndex`; A2 declines a second `HttpCache` method |
| User CLAUDE.md — pre-1.0, no backward-compatibility shims | Compliant | The C2 config rename takes the clean break rather than an alias |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|--------------|------------|
| The shared `registries.workspace_registries` means an npm user setting `all` also widens Cargo's SSRF gate | Medium — a security setting with a broader blast radius than its user expects | Medium | The rename itself is the mitigation (the key no longer *looks* ecosystem-scoped); documented explicitly in `README`/`ECOSYSTEM_GUIDE` and in NFR-003. Per-ecosystem policy is the tracked follow-up (needs an `HttpCache`/`Transport` refactor) |
| Config key rename rejects the **whole** settings payload, not just the renamed section (N-S2) | Medium-High — at `initialize` every section reverts to its default, announced only in the log | High (anyone who set it) | Fails *closed* on the security-relevant setting (`public_only` is the default and `HttpCache::new`'s starting policy), so this is not a security regression. Mitigated by documentation accuracy rather than code: the CHANGELOG "Breaking" entry, README and ECOSYSTEM_GUIDE must state the full blast radius per §2's N-S2 framing. A transitional `cargo` alias stays rejected (pre-1.0 no-shims); revisit only if a user reports the silent-revert in practice |
| Alternate-sourced dependencies silently drop out of OSV scanning (M3) | Low — correct behavior, but surprising | High (by design) | Documented in `ECOSYSTEM_GUIDE.md` and in `NpmFormatter`'s code comment as a deliberate consequence of the `source_is_public_registry_content` default |
| Freshness/age hints missing for private-registry dependencies (A2) | Low — cosmetic | High (by design in phase 1) | Documented limitation; the follow-up is a workspace-gated `get_transport_only_*` |
| `dirs` introduces a platform-specific home-dir bug on an untested container shape | Medium — `~/.npmrc` silently not found | Low | Thin, widely-used wrapper; unit test asserting the resolved path matches `$HOME`/`%USERPROFILE%` on CI platforms |
| A future contributor "just also parses" the `_authToken` line a project `.npmrc` legitimately carries | High if it happens | Low | FR-013/NFR-001's structural enforcement makes it a deliberate type change, not a one-line addition; flagged in code comments and by the §7 CI grep gate |
| `NpmRegistryIndex`/`NpmConfig` duplicating `deps-cargo::config`'s shape reads as accidental divergence | Low | Medium | §1 NFR-002 documents *why* promotion is deferred and what triggers it (the auth-wiring spec) |

## 12. Critic Finding Disposition

### r3 — second critic pass (`.local/handoff/2026-09-02T19-32-08-critic.md`)

Every claim below was re-verified against source by this revision, independently
of both the critic's and r2's readings — the r1 critic and the r2 architect each
asserted something as verified that was not, so nothing in this table is taken on
report alone.

| ID | Disposition | Where |
|----|-------------|-------|
| **N-C1** r2 inverted S6; FR-006/NFR-002 mandate a release-build `http`-loopback exception `deps-core` rejects | **Accepted, and the critic is right on every point.** Verified directly: `deps-cargo/src/config.rs:185` carries `#[cfg(any(test, feature = "test-util"))]` above `fn is_loopback_url`; `deps-core/src/cache.rs:121` gates `is_loopback_host` identically and `ensure_https` (`:151-160`) consults it only under that cfg. Also verified the unreachability claim: `get_cached_workspace` (`cache.rs:1041-1048`) delegates to `get_cached_with_headers_via` (`:1074`), whose two send paths `conditional_request_with_headers` (`:1149`) and `fetch_and_store_with_headers` (`:1224`) each call `ensure_https` at `:1158` and `:1232` — so a release-build `http://localhost` index would indeed reach `CacheError("URL must use HTTPS")` rather than any usable outcome. r2's wording was net worse than both alternatives. Build-gated rule restored, with the reachability argument (not just the mirror-`deps-cargo` argument) written into the design so it cannot be "simplified" back out. The `deps-core` `ensure_https` change that would be needed to genuinely allow it stays out of scope, per §8 "Ask First" | §1 (`NpmRegistryIndex::new` doc, entity summary), §3, §6 NFR-002 bullet, §7 (mockito row reason + a new scheme-gate row), spec FR-006/NFR-002/§5/§6, and the S6 row above |
| **N-S1** unregistered-`AlternateRegistry` fetch fallthrough unspecified | **Accepted; the recommended *behavior* is confirmed, but the task brief's suggested mechanism is not what Cargo does.** Verified `deps-cargo/src/registry.rs:489-547`: the arms are `Some(client)` → alternate, `None if *mirrors_crates_io` → crates.io, `None` → `Err(PackageNotFound{registry:"alternate registry (not registered)"})`, `_` → crates.io — and the comment at `:529-532` does record the enumeration being "wrong twice during design review". Cargo does **not** lazily create a client on the fetch path: the only `register_alternate` call site in the workspace is parse-time (`deps-cargo/src/ecosystem.rs:248`). Lazy creation is also not *constructible* on npm's fetch path, which holds only the validated `index: String` and not the `RegistryAccessPolicy` an `NpmRegistryIndex` requires. So npm keeps parse-time-only registration with an unconditional `PackageNotFound` on the `None` arm (npm's `mirrors_crates_io` is always `false`, so Cargo's mirror arm is dead and must not be written) | §3 new "dispatch (N-S1)" subsection, §5 alternate-registry row, §7 new integration row, spec FR-010 + a new §6 edge-case row |
| **N-S2** C2's rename blast radius understated in §2/§9/§11 | **Accepted; both sub-claims verified.** `#[serde(deny_unknown_fields)]` is on `DepsConfig` itself (`deps-lsp/src/config.rs:34`, and its own doc at `:25-32` says so explicitly), so a stale `cargo` key fails the whole payload. At `initialize` (`server.rs:385-395`) the `if let ... && let Some(config) = parse_config(...)` chain is simply skipped on failure, leaving `Backend::new`'s `DepsConfig::default()` (`:79`) — a full reset, not a "keep previous". Confirmed fail-closed for the security setting: `WorkspaceRegistriesSetting::default()` is `PublicOnly` and `HttpCache::new` constructs from `RegistryAccessPolicy::default()` (`cache.rs:708-714`), so the skipped `set_registry_policy` is harmless. `didChangeConfiguration` (`server.rs:516-518`) does early-return and keep the live config, so the old wording was right for that case only. Wording corrected to cover both; the C2 decision itself is **not** reversed — the alias remains rejected on the pre-1.0 no-shims rule | §2 (new N-S2 block), §9, §11 |
| **N-M1** `get_cached_workspace_with_headers` needs a redirect/credential doc warning | **Accepted.** Verified the precedent at `cache.rs:948-962`, which documents exactly this hazard for `get_cached_trusted_origin_with_headers` and explains that origin-pinning is what closes it. The workspace transport pins by host *class*, not origin, so the new method has the hazard the trusted-origin one was built to avoid | §2 A1 doc requirement |
| **N-M2** "delete `CargoConfig`" is ambiguous; two extra edit sites omitted | **Accepted.** Verified two distinct types: `deps_lsp::config::CargoConfig` (`config.rs:636`, one field, the one to delete) and `deps_cargo::config::CargoConfig` (`deps-cargo/src/config.rs:358`, re-exported at `deps-cargo/src/lib.rs:33`, unrelated and untouched). Edit sites in `deps-lsp/src/config.rs` enumerated exactly: `:51`, `:630-632`, `:636`, `:747`, `:769-770`, `:773` | §2 |
| **N-M3** an alternate inherits `search`, which uses the ungated transport | **Accepted, and enforced rather than merely documented.** Verified `registry.rs:468-478` — `search` calls `self.cache.get_cached(&url)` (baseline transport) against `self.registry_base`. Unreachable under the plan's routing today, but nothing enforces it. `search` now returns an empty `Vec` for `tier == WorkspaceDeclared`, with a test row | §3 invariants list, §7 |

### r2 — first critic pass (`.local/handoff/2026-09-02T19-15-42-critic.md`)

Every finding in that report. "Verified" means the r2 revision re-read the cited
source itself — with the one exception of **S6**, whose disposition r3 rejects
(see N-C1 above).

| ID | Disposition | Where |
|----|-------------|-------|
| **C1** unresolved state has no mechanism | **Accepted.** Verified `parser.rs:875-882` + `:944`. Resolves to `CustomRegistry { url: raw }`; `RegistryResolution` deleted; `resolve_source_for` returns `DependencySource` directly | §1 approach table + "Where unresolved lives" row (rewritten), §3 |
| **C2** `npm.workspace_registries` collides with the single global policy | **Accepted**, resolved per the user's decision. Verified `cache.rs:1060`, `state.rs:494-508`, `server.rs:391,523`. One shared setting, renamed `cargo.workspace_registries` → `registries.workspace_registries`; `CargoConfig` deleted (it had exactly one field) | §1 policy-scope row, §2, §4, §9 |
| **C3** completion fails open to the public registry | **Accepted.** Verified `completion.rs:875` (`get_versions_with`, source-blind) and `deps-npm/src/ecosystem.rs:65-78`. New FR-017 in spec; Cargo's `CompletionSource`/`resolve_completion_source`/`alternate_client` pattern adapted | New spec FR-017; §1 FR-017 row, §3, §7 |
| **S1** alternate fetches must use `get_cached_workspace` | **Accepted.** Verified `sparse.rs:375-376` and npm's `get_cached_with_headers` at `registry.rs:266`. `NpmRegistryTier` selects the transport | §1 transport row, §5, §6 |
| **S2** `find_workspace_root` does not exist; cache is wrong-shaped | **Accepted on substance; the supporting evidence is partly wrong.** `rg find_workspace_root crates/` returns four hits, not zero — but all are a doc comment and two test names (`deps-cargo/src/parser.rs:580,717,1336`); the function was renamed to `discover_workspace` (`parser.rs:604+`), which *does* compute a `workspace_root: Option<PathBuf>`. So Cargo does have a workspace-root concept — it is just for `[workspace]` manifest discovery, **not** for config caching, and `ConfigFileCache` is keyed per file path exactly as the critic says (`config.rs:645-712`). The recommendation stands unchanged: `NpmConfigCache` is keyed by `.npmrc` path, with no workspace-root concept | §1 FR-012 row, §3 |
| **S3** `deps-lsp` wiring omitted | **Accepted.** Verified `lib.rs:253-286` (policy is *moved* into `CargoParseContext`), the `register!` macro at `:25-30` (`NpmEcosystem::new(cache)` → default policy), and `server.rs:391,523`. All three files now listed with the specific change each needs; `NpmParseContext` gains the missing `policy` field | §2, §3 |
| **S4** `${VAR}` expansion unspecified | **Accepted**, resolved per the user's decision: a defined var expands, an undefined one is FR-007-invalid; expansion is confined to the two registry key shapes, so no auth key is ever expanded | §1 `${VAR}` row, §6, §7 |
| **S5** index URL normalization missing | **Accepted.** Verified `versions_url` at `registry.rs:118-129` (`{base}/{name}`) and US-001's trailing-slash example. Trailing-slash normalization added to `NpmRegistryIndex`; the `alternates` map is keyed by the normalized `as_str()` on both sides | §3 |
| **S6** "https except loopback in test builds" is wrong | **REJECTED in r3 — r2 accepted this in error; see N-C1.** r1's original "in test builds" qualifier was correct and r2 removed it on a misreading of the source. `is_loopback_url` **does** carry `#[cfg(any(test, feature = "test-util"))]` (`deps-cargo/src/config.rs:185`, immediately above the `fn`, inside the range r2 cited as evidence it did not), and `deps-core`'s `is_loopback_host`/`ensure_https` are gated identically (`cache.rs:121,151-160`). The build-gated rule is restored throughout. The §7 mockito rows survive — a test build enables the carve-out and the policy-must-be-`All` note stays true — but their stated *reason* is rewritten: those tests depend on two gates, not one | §1, §3, §6, §7, and the N-C1 row below |
| **M1** `AlternateNpmClient` is invented | **Accepted.** Verified `registry.rs:177-206` — `build` is private and `with_registry_base` is `#[cfg(any(test, feature = "test-util"))]`. No new type; add an ungated `with_base(cache, &NpmRegistryIndex)` | §3 `NpmRegistry` extension |
| **M2** `alternates` must be `Arc<DashMap>` | **Accepted.** Verified `#[derive(Clone)]` on `NpmRegistry` and the clone at `lib.rs:281`. Also added: each alternate needs its **own** `publish_times`, since that map is keyed by bare package name and would otherwise collide across registries | §3 |
| **M3** name the hover-link hook; note the OSV side effect | **Accepted.** Verified `suppress_package_url` at `lsp_helpers/mod.rs:1531` and `source_is_public_registry_content`'s default just above at `:1449`. Both named; the OSV drop-out is documented as deliberate and routed to `ECOSYSTEM_GUIDE.md` | §3 entity summary, §11 |
| **M4** SC-002 cannot hold literally | **Accepted.** Verified ~10 direct `complete_versions` call sites in `deps-npm/src/ecosystem.rs`'s tests and Cargo's `empty_parse_result()` helper at `deps-cargo/src/ecosystem.rs:374-377`. Spec SC-002 reworded; the expected fixture churn is stated | §7 M4 note; spec SC-002 |
| **M5** SC-003's grep will match its own test fixtures | **Accepted.** Gate scoped to non-test sources, with a fallback (move fixtures to `tests/fixtures/`) if the `mod tests` exclusion proves brittle; `.github/workflows` added to §2 | §2, §7 |
| **M6** scope key format and case-folding unspecified | **Accepted.** Key is `@scope` **with** the `@`, byte-exact, no case folding — matching npm's own literal `@${scope}:registry` concatenation against byte-exact ini keys. Folding would resolve a registry npm itself would not, which is the FR-006 divergence direction the spec forbids | §3 `NpmConfig` doc, §7 |
| **M7** missing test rows for FR-003/008/009/015 | **Accepted.** Four rows added, plus new rows for FR-017, S5, M6 and M9 | §7 |
| **M8** "Where unresolved lives" row is broken | **Accepted.** Row rewritten from scratch, not patched — it is C1's carrier | §1 |
| **M9** ancestor walk / `$HOME` collision, no dedupe | **Accepted.** Verified `deps-cargo/src/config.rs`'s `load_tiers` canonicalized-path filter. Canonicalized-path dedupe added; the deliberate divergence from npm's project-root-only read is now stated | §5 |

### Additional gaps r2 found while re-verifying (not in the first critic's report)

| ID | Finding | Resolution |
|----|---------|------------|
| **A1** | S1's fix is not directly available: `HttpCache::get_cached_workspace` takes **no headers** (`cache.rs:1041`), but npm's `get_versions` needs the abbreviated-packument `Accept` header (`registry.rs:266`) — without it every alternate fetch pulls the full multi-MB packument | Add `HttpCache::get_cached_workspace_with_headers`, the headered form, mirroring the `get_cached` / `get_cached_with_headers` pair. Inherent method on a struct, not a trait-surface widening, so the spec's "Never widen the `deps-core` `Registry`/`EcosystemFormatter` trait surface" boundary is untouched. `crates/deps-core/src/cache.rs` added to §2 |
| **A2** | There is **no** workspace-gated `get_transport_only_*` variant at all (enumerated every public fetch method in `cache.rs`), and npm's freshness path uses `get_transport_only_with_headers` (`registry.rs:336`). Routing an alternate's full packument through the ungated transport would reopen the S1 redirect hole | Phase 1 skips publish-times entirely for `WorkspaceDeclared` clients — an empty map, which `fetch_publish_times` already treats as its normal degradation. Private-registry dependencies lose only the relative-age suffix. A workspace-gated transport-only method is the follow-up |

## See Also

- [[spec]] — feature specification
- [[023-cargo-custom-registries/plan|023-cargo-custom-registries plan]] — the reference implementation this plan mirrors
- `.local/handoff/2026-09-02T19-32-08-critic.md` — the second critic pass r3 answers
- `.local/handoff/2026-09-02T19-15-42-critic.md` — the first critic pass r2 answered
- `crates/deps-core/src/parser.rs` — `DependencySource::{Registry, CustomRegistry, AlternateRegistry}`, `is_version_resolvable`
- `crates/deps-core/src/cache.rs` — `HttpCache`, `get_cached_workspace`, `set_registry_policy`
- `crates/deps-core/src/completion.rs` — `complete_versions_generic` (the source-blind call FR-017 stops relying on)
- `crates/deps-core/src/lsp_helpers/mod.rs` — `can_resolve_source`, `source_is_public_registry_content`, `suppress_package_url`
- `crates/deps-cargo/src/config.rs` — `RegistryIndex`, `IndexTrust`, `ConfigFileCache`, `load_tiers`
- `crates/deps-cargo/src/registry.rs` — `alternates`, `register_alternate`, `alternate_client`, `MAX_ALTERNATE_REGISTRIES`
- `crates/deps-cargo/src/ecosystem.rs` — `CompletionSource`, `resolve_completion_source`, `empty_parse_result`
- `crates/deps-cargo/src/sparse.rs` — the `IndexTrust` → transport selection this plan mirrors
- `crates/deps-lsp/src/{config.rs,server.rs,lib.rs}` — the policy/config wiring this plan changes
- `crates/deps-npm/src/{registry.rs,parser.rs,formatter.rs,ecosystem.rs,lib.rs}` — current npm crate state
- [[MOC-specs]] — all specifications

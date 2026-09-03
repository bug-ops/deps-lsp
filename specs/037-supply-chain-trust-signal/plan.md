---
aliases:
  - Supply-Chain Trust Signal Plan
  - deps.dev Integration Plan
tags:
  - sdd
  - plan
  - deps-core
  - supply-chain-risk
created: 2026-09-03
updated: 2026-09-03
status: draft
related:
  - "[[spec|037 Supply-Chain Trust Signal spec]]"
  - "[[MOC-specs]]"
---

# Plan: Supply-Chain Trust Signal (deps.dev)

> [!info] Scope
> Phase 2 (HOW) for [[spec|037-supply-chain-trust-signal]]. Issue #543,
> branch `feat/543-supply-chain-trust-signal`. Architecture only — no code
> written by this phase.

## 1. Live API re-verification (2026-09-03, this session)

Everything below was probed against the live API before designing against it.

| Probe | Result |
|-------|--------|
| `system` path segment casing | Case-insensitive — `npm`/`NPM`, `cargo`/`CARGO`, `rubygems`/`RUBYGEMS` all `200`. Plan uses lowercase. |
| Package name in path | Must be percent-encoded as **one** segment. `golang.org%2Fx%2Ftext` → `200`; raw `golang.org/x/text` → **`404`**. `com.google.guava%3Aguava`, `%40types%2Fnode` → `200`. |
| PyPI name normalization | Server-side. `Flask-SQLAlchemy` and `flask_sqlalchemy` both `200`. |
| NuGet name casing | Server-side. `Newtonsoft.Json` and `newtonsoft.json` both `200`. |
| `scorecard.overallScore` | Present, `8.5` for `github.com/expressjs/express`. Siblings: `date`, `repository`, `scorecard{version,commit}`, `metadata`, `checks[]`. |
| `slsaProvenances[]` / `attestations[]` entries | Each carries **`verified: bool`** plus `sourceRepository`, `commit`, `url`, and (attestations) `type`. |
| `relatedProjects[]` | **Multiple `SOURCE_REPO` entries per package**, differing only in `relationProvenance` (`UNVERIFIED_METADATA` vs `SLSA_ATTESTATION`). |
| Cache validators | **No `ETag`. No `Last-Modified`.** Only `cache-control: public, max-age=3600`, on both endpoints. |
| 404 body | `text/plain`-ish (`version not found`), not JSON. |

Three of these invalidate assumptions the spec builds on; see §10.

## 2. Crate and module placement

`deps-core`, new module, mirroring the `osv/` layout one-for-one:

```
crates/deps-core/src/deps_dev/
├── mod.rs      DepsDevClient, two-call sequence, TTL memo, system mapping
└── types.rs    wire types (serde) + SupplyChainTrustSignal
```

- `pub mod deps_dev;` in `lib.rs`, alphabetically between `completion` and
  `ecosystem`; re-export `SupplyChainTrustSignal` at the crate root per
  `.claude/rules/rust-code.md`. `DepsDevClient` stays module-qualified
  (matches `osv::OsvClient`).
- `deps-core` is correct, not an ecosystem crate: seven ecosystems consume it,
  and `ServerState` must hold the client with no `#[cfg(feature = ...)]` gate —
  the identical argument `net_policy.rs`'s module docs already make. NFR-006 is
  satisfied by the module boundary: no deps.dev field lands in any ecosystem
  crate's registry-response types.
- `crates/deps-core/Cargo.toml`: `urlencoding` must become unconditional for
  production path-segment encoding. This is a **3-line change, not one**
  (critic M5) — done as one line it will not compile:
  1. `:48` `urlencoding = { workspace = true, optional = true }` → drop
     `optional = true`;
  2. `:31` `test-util = [.. "dep:urlencoding"]` → remove that entry, since
     Cargo errors when `dep:` names a non-optional dependency;
  3. `:57` the dev-dependencies entry becomes redundant and should go.

## 3. Types

In `deps_dev/types.rs`. Wire types are `#[derive(Deserialize)]` with
`#[serde(rename_all = "camelCase")]`; serde ignores unknown fields by default,
so only what is consumed is declared.

```rust
// ---- wire (deps.dev) ----
struct DepsDevVersionInfo {
    slsa_provenances: Vec<ProvenanceEntry>,   // #[serde(default)]
    attestations:     Vec<ProvenanceEntry>,   // #[serde(default)]
    related_projects: Vec<RelatedProject>,    // #[serde(default)]
}
struct ProvenanceEntry { verified: bool }     // #[serde(default)]
struct RelatedProject {
    project_key:          ProjectKey,         // { id: String }
    relation_type:        String,
    relation_provenance:  String,             // #[serde(default)]
}
struct DepsDevProject { scorecard: Option<DepsDevScorecard> }
struct DepsDevScorecard {
    overall_score: Option<f32>,               // NOT #[serde(default)] — see below
}

// ---- public, ecosystem-agnostic (consumed by hover) ----
pub enum ProvenanceStatus { Verified, Unverified, None }

pub struct ScorecardSummary {
    pub overall_score: f32,     // only constructed from a parsed 0.0..=10.0 value
    pub self_reported: bool,    // §5's pick landed on UNVERIFIED_METADATA
}

pub struct SupplyChainTrustSignal {
    pub scorecard:  Option<ScorecardSummary>,
    pub provenance: Option<ProvenanceStatus>,
}
```

Deltas from spec §5, all upward in precision — each needs lead sign-off (§10):

- `ScorecardCheck` / `checks: Vec<_>` / `scorecard.version` are **dropped**.
  FR-003 mandates only `overallScore`; parsing ~20 checks per hover to render
  none of them is unused surface the MVP rule and clippy both push back on.
  Adding them later is additive.
- `provenance_verified: Option<bool>` becomes `Option<ProvenanceStatus>`. The
  live entries carry `verified: bool`; collapsing a non-empty-but-unverified
  array to "verified" would print a **false trust claim**, which is worse than
  printing nothing. Mapping: any entry `verified == true` → `Verified`;
  non-empty but none verified → `Unverified`; both arrays empty → `None`.
- `RelatedProject` gains `relation_provenance` — load-bearing, see §5.
- `ScorecardSummary.self_reported` carries §5's ranking outcome forward to the
  renderer, so the O5 disclosure marker costs no extra request or parse.
- `overallScore` is **`Option<f32>` on the wire with no `#[serde(default)]`**,
  and `ScorecardSummary` is built only when it parses to a finite value in
  `0.0..=10.0`; anything else (absent, null, unparseable, out of range) →
  `scorecard = None`, section half omitted. A `#[serde(default)]` `f32` would
  render an unscored project as "**OpenSSF Scorecard `0`/10**" — maximally
  damning for a project deps.dev simply has no Scorecard for, and the same
  class of false trust claim D3 exists to prevent (critic S3).
- `ScorecardSummary.date` and `.project_id` are **dropped**. O3 settled that v1
  renders no age qualifier and §8 forbids a hyperlink, so both would be parsed
  and never read — D4's own argument against `checks[]` applies unchanged
  (critic M8). Re-add `date` if O3 is ever revisited; `project_id` is not
  needed by the O5 marker, which only needs the boolean.

## 4. Client and the two-call sequence

```rust
pub struct DepsDevClient {
    cache:    Arc<HttpCache>,
    base_url: String,            // DEPS_DEV_API in prod; mockito URL in tests
    trusted_origin: String,      // format!("{base_url}/")
    memo:     DashMap<MemoKey, MemoEntry>,
    projects: DashMap<ProjectKeyMemo, ProjectMemoEntry>,   // §6, critic M2
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct MemoKey {
    base:    String,
    system:  &'static str,
    name:    String,
    version: String,
}

struct MemoEntry {
    fetched_at: Instant,
    ttl:        Duration,
    /// The **outcome**, negative results included — a memoized `None` is what
    /// makes "zero requests on a repeat call" hold on the failure path too.
    signal:     Option<SupplyChainTrustSignal>,
}

impl DepsDevClient {
    pub fn new(cache: Arc<HttpCache>) -> Self;
    pub fn for_test(cache: Arc<HttpCache>, base_url: impl Into<String>) -> Self;

    /// Infallible. `None` == nothing to render.
    pub async fn trust_signal(
        &self, system: &'static str, name: &str, version: &str,
    ) -> Option<SupplyChainTrustSignal>;
}
```

`MemoKey` is a **typed tuple, not a `\0`-joined string** (critic S5). The
`format!("{base}\0{system}\0{name}\0{version}")` shape copied from
`github.rs:662` is only collision-free there because `validate_owner_repo`
rejects the name first; here `name` comes from a manifest and `version` from
`in_use_version`, whose lockfile `ConcreteVersion` branch
(`in_use_version.rs:306-309`) is never charset-validated — so `("a\0b", "c")`
and `("a", "b\0c")` would collide and **serve another package's trust signal**.
A derived `Hash`/`Eq` over four fields cannot collide by construction, which is
cheaper than auditing every producer's charset forever.

`new`/`for_test`/`trusted_origin` copy `github::GithubTagsClient` (github.rs:180-218)
verbatim in shape — the established pattern for a shared third-party API client
in this crate.

Sequence inside `trust_signal`:

1. **Memo read.** `base` is in the key for the same reason `ReleaseDatesCache`
   includes `api_base` (github.rs:655-662): a mock-server hit must never serve
   a real-API read. Fresh entry → return its clone, **zero requests** —
   including when the memoized outcome is `None`.
2. **Version call.** `GET {base}/v3/systems/{system}/packages/{enc(name)}/versions/{enc(version)}`.
   On success → `provenance = Some(status)` per §3's mapping, and the
   `relatedProjects[]` pick per §5. On any failure → `provenance = None` and no
   project key, so step 3 is skipped and the whole result is `None`
   (spec §6: "both queries fail → entire section omitted").
3. **Project call**, only if step 2 yielded a usable project key:
   `GET {base}/v3/projects/{enc(project_key)}`. On success → `scorecard =
   Some(..)`. On failure → `scorecard = None`, `provenance` from step 2 is
   **kept** (spec §6: "version query succeeds, project query fails → provenance
   still shown").
4. **Memo write**, then return. TTL by outcome:

   | Outcome | TTL | Why |
   |---------|-----|-----|
   | Any signal assembled | 1 h | the server's declared `max-age=3600` |
   | **HTTP 404** on either call | 1 h | a *definitive* "deps.dev has no record", not a transient fault — the short TTL would re-fire 1-2 requests every 90 s of hovering any private/internal/brand-new package, exactly the storm `github.rs:447-452` warns about (critic M1) |
   | Network error, timeout, 5xx, malformed JSON | 90 s | genuinely transient; value from `RELEASE_DATES_ERROR_TTL` |

Strictly sequential — step 3's URL comes out of step 2's body — so a cold
hover costs exactly 2 round-trips. **Two nested bounds, not one:**

- `DEPS_DEV_CALL_TIMEOUT = 400 ms` per call, so step 3 hanging can never
  discard step 2's already-successful provenance (the partial-failure
  requirement in §4 step 3).
- `DEPS_DEV_TOTAL_BUDGET = 700 ms` around the **whole** sequence, which is what
  actually bounds what a hover can wait for. Without it the two per-call
  timeouts stack to ~800 ms and the sequence has no single ceiling — critic S1.

Worst case a hover *renders* 700 ms late; see §8, which removes even that from
the user-visible path.

**Failure representation.** Internally every step is `deps_core::Result<Bytes>`
from `HttpCache` plus `serde_json::Result`; both are swallowed at the
`trust_signal` boundary, which never returns `Err`. Precedent:
`OsvClient::scan` ("never fails", osv/mod.rs:13-15) and
`ReleaseDatesCache::fetch` ("best-effort by construction", github.rs:611-621).
Logging is `tracing::debug!` only — never `warn!`/`error!` — so FR-006's
"no error/warning surfaced" holds. `HttpCache` itself emits one
`tracing::warn!` on its stale-fallback path (cache.rs:1158); §6's transport-only
call site avoids that path entirely, so no pre-existing warn is inherited.

Every field of `SupplyChainTrustSignal` being `None` is normalized to
`Option::None` at the return, so hover's render helper only ever sees a signal
that has something to say.

## 5. Choosing the SOURCE_REPO project key

FR-002 says "contains an entry with `relationType == "SOURCE_REPO"`" — but the
live response carries **several**, distinguished by `relationProvenance`. A
deterministic, security-aware pick:

1. `relation_type == "SOURCE_REPO"` **and** `relation_provenance == "SLSA_ATTESTATION"` — cryptographically backed.
2. Otherwise the first `relation_type == "SOURCE_REPO"` (typically `UNVERIFIED_METADATA`).
3. No such entry → `scorecard = None`, provenance still rendered (FR-005, NFR-004).

Case 2 sets `ScorecardSummary.self_reported = true`, which §8 renders as an
explicit disclosure — a Scorecard for a merely-claimed repository must not carry
the same visual confidence as one for an attested repository.

This matters beyond determinism: `UNVERIFIED_METADATA` is derived from the
package's own manifest metadata, so a hostile package can point its repository
field at a reputable, high-scoring repo and **inherit that repo's Scorecard**
in the hover. The spec's Assumptions accept trusting deps.dev's relation as
given, so preferring the attested relation is the cheapest available mitigation
without new scope. Ranked as a residual risk for the security reviewer, not
solved by this plan.

**Project-key validation before URL interpolation.** `projectKey.id` is
third-party-controlled text spliced into a request path. Note precisely what
this does and does not buy (critic M4): encoding the key as **one** segment
already defeats traversal on its own — `evil/../secret` becomes
`evil%2F..%2Fsecret`, which contains no `..` *segment* — so validation is not
the traversal defence. Its real value is rejecting junk before it costs a
request, and keeping a malformed third-party id out of a URL at all. Concretely,
reject unless:

- there are 2-4 `/`-separated segments, none empty;
- no segment is `.` or `..` (`deps_core::lsp_helpers::is_dot_segment`);
- the first segment is host-shaped: at least one `.`, and every dot-separated
  label non-empty, `[A-Za-z0-9-]` only, not starting or ending with `-`;
- every remaining segment matches `[A-Za-z0-9._-]+`.

That last rule **over-rejects non-ASCII repository names**, which is
intentional: the failure mode is one missing hover section for a rare repo,
against the alternative of hand-auditing Unicode in a URL path. Then
percent-encode the **whole key as one path segment** via
`urlencoding::encode` (`github.com/expressjs/express` →
`github.com%2Fexpressjs%2Fexpress`, live-verified). Same encoding rule for
`name` and `version` in step 2 — required, not cosmetic: the raw-slash Go probe
404s.

## 6. HttpCache and net_policy call sites

**The finding that drives this section: deps.dev sends no `ETag` and no
`Last-Modified`.** With no validators, `HttpCache::get_cached_with_headers_via`
issues a plain GET on every call and takes the `Ok(Some(new_body))` arm
(cache.rs:1145-1156) — a **full-body re-fetch per hover**, since `HttpCache`
has no TTL/freshness window at all. So FR-007's letter is satisfiable while its
intent (NFR-001 "reuses a cached or 304-revalidated response") is not, and
SC-005 ("assert the 304 path is exercised") is **unsatisfiable by construction**.

Resolution — the same one `osv/mod.rs:5-11` already documents for OSV.dev's
identical missing-validators problem, and the same shape
`github::ReleaseDatesCache` uses:

- **Transport, policy, and limits: reuse `HttpCache`.** Call site is
  `HttpCache::get_transport_only_with_headers_limited_trusted_origin(url, &[],
  BodyLimit::new(1 MiB), &self.trusted_origin)` (cache.rs:1419). This one call
  reuses, unchanged: `ensure_online` (so `network.offline` gates deps.dev for
  free), `ensure_https`, the `BlockedAddrResolver` DNS guard, the body-size cap,
  and the origin-pinned redirect policy.
- **Caching: a TTL memo inside `DepsDevClient`**, over the *assembled*
  `SupplyChainTrustSignal`, not over response bodies. Success TTL **1 h**
  (the server's own declared `max-age=3600` — not a guessed number); error TTL
  **90 s**, and 404 at the 1 h success TTL — the full table is in §4 step 4.
  `MAX_MEMO_ENTRIES = 512`.
- **Eviction: a new helper modelled on `evict_release_dates_if_full`
  (github.rs:487-501)**, not a reused one — the "percentage-eviction helper
  both modules already use" this plan previously claimed **does not exist**
  (critic S6). github.rs's policy is *expired-first, then the single oldest by
  `fetched_at`*, which is the right shape for a TTL-carrying memo. `osv`'s
  `evict_oldest` (osv/mod.rs:101-120) is not an option: it is private to that
  module and hardwires `MAX_CACHE_ENTRIES / CACHE_EVICTION_PERCENTAGE` = 1000
  removals, which against a 512-entry memo empties it on every full insert.
  Either write the 14-line equivalent beside this memo or generalize
  github.rs's over its bound and entry type — developer's call, but it is new
  code either way, not a call to something existing. Refreshing an existing key
  skips eviction (github.rs:696-700).
- **A second memo keyed by validated project key** (critic M2), holding the
  `ScorecardSummary` from step 3. The Scorecard is a property of the *project*,
  not the version, so without it hovering five `@babel/*` packages fires five
  identical `GET /v3/projects/github.com%2Fbabel%2Fbabel` calls. Same TTL table,
  same eviction policy. This is where NFR-001's "treat conservatively" is
  actually earned on a real manifest.
- Transport-only, not entry-cached, deliberately: the memo owns caching, so
  storing bodies in `HttpCache`'s 64 MiB entry map too would double-cache and
  evict genuinely reusable registry bodies for nothing.

This is a **documented deviation from FR-007/NFR-002 and it retires SC-005** —
see §10. It keeps FR-007's actual prohibition ("rather than introducing a
parallel caching mechanism") intact: no second HTTP client, no second entry
map, and the memo pattern is this crate's existing one, not a new invention.

**net_policy (FR-008): no change required, and the §8 "Ask First" gate does not
fire.** `transport_for_origin` builds `Transport::origin_pinned`, which pairs
`AddrGuard::Baseline` with `trusted_origin_redirect_policy`
(cache.rs:547-556). `AddrGuard::Baseline::tier_allows` returns `true`
unconditionally (cache.rs:220-222), so `api.deps.dev` is **not** subject to
`WorkspaceRegistryAccess` — exactly FR-008's "fixed, non-workspace-configurable
trusted-origin endpoint", already true by construction.

Correcting this plan's earlier description of the mechanism (critic M3 — the
conclusion above is unaffected, but the reasoning misstated where the
classifier runs): `trusted_origin_redirect_policy` (cache.rs:290-298)
**does not call** `hop_targets_blocked_host`, because the URL-prefix pin
already subsumes a per-hop host check — documented at cache.rs:544-546.
`net_policy::classify_host` therefore runs on **resolved addresses** via
`BlockedAddrResolver`, not on redirect hops, for this transport. Task #6's
security reviewer should read it that way. No new `HostClass` variant, no new
policy tier, nothing to ask the user about.

**NFR-005** holds trivially: `extra_headers` is `&[]` at the one call site.

## 7. Ecosystem mapping — an exhaustive `match`, no new trait

> [!warning] Revised after critic S4
> This section previously specified a `DepsDevNaming` concern trait added to
> `EcosystemFormatter`'s supertrait list, and claimed the uncovered ecosystems
> "need zero code". **That claim was wrong.** Adding an eighth supertrait
> (formatter.rs:762-783) makes every current implementor stop satisfying the
> blanket impl until it adds `impl DepsDevNaming for X {}` — **55 sites across
> 27 files**, 8 of them inside rustdoc examples that the CI doc-test gate would
> fail on. The trait is dropped entirely.

Both pieces the client needs turn out not to require per-ecosystem behaviour:

- **`system`** does not depend on the dependency at all, only on the
  ecosystem — and `VersionData.ecosystem: Option<EcosystemId>` already carries
  that, always set by `handlers/hover.rs:68`.
- **the name** is `dep.name()` unmodified for all seven. The critic confirmed
  each against the worktree: Maven names already are `group:artifact`; PyPI and
  NuGet are normalized server-side (§1); Go keeps its `v` prefix through
  `looks_like_a_single_version` (in_use_version.rs:126).

So `deps_dev/mod.rs` carries one function and nothing else:

```rust
pub(crate) const fn deps_dev_system(id: EcosystemId) -> Option<&'static str> {
    match id {
        EcosystemId::Npm     => Some("npm"),
        EcosystemId::Cargo   => Some("cargo"),
        EcosystemId::Go      => Some("go"),
        EcosystemId::Maven   => Some("maven"),
        EcosystemId::Pypi    => Some("pypi"),
        EcosystemId::Bundler => Some("rubygems"),
        EcosystemId::NuGet   => Some("nuget"),
        EcosystemId::Composer | EcosystemId::Dart | EcosystemId::Swift
        | EcosystemId::Gradle | EcosystemId::Deno
        | EcosystemId::GithubActions => None,
    }
}
```

**No `_` wildcard arm** — that is the whole point. §11 previously rejected a
central match on the grounds that "a new ecosystem silently defaults to some
arm"; with the uncovered variants named explicitly, adding a fourteenth
`EcosystemId` is a **compile error** until someone decides which side it
belongs on. That is strictly stronger than a trait default of `None`, which
silently opts a new ecosystem out. FR-005 and FR-011 now hold by *compiler
enforcement* rather than by inheritance, at a cost of one function instead of
55 impl blocks.

The trade accepted: if an ecosystem ever needs a genuine name transform, the
trait comes back for that method alone. Nothing today needs one, and building
the extension point before the first real divergence is exactly the premature
abstraction the MVP rule forbids.

Deliberately **not** covered, though both would be one-line arms: `deps-gradle`
(Maven coordinates — deps.dev's `maven` system covers them) and Deno's `npm:`
specifiers. FR-001 enumerates seven ecosystems and Gradle is not among them
(D8); the follow-up is trivial either way.

## 8. Hover integration

**The signal is fetched inside `lsp_generate_hover`, concurrently with the
registry fetch, for the one hovered dependency only.**

Plumbing, chosen to require **no** signature change in any ecosystem crate:

1. `ServerState` (state.rs:471-514) gains `pub deps_dev: Arc<DepsDevClient>`
   beside `cache` and `osv`, built as
   `DepsDevClient::new(Arc::clone(&cache))`.
2. `VersionData` gains one field and builder:
   `pub trust: Option<&'a Arc<DepsDevClient>>` / `with_trust(client)`. It
   already carries non-version context (`ecosystem`, `offline`), so this fits
   the type it actually is. `&Arc`, not `&`, so the fetch can be cloned into a
   detached task — see the latency design below.
3. `handlers/hover.rs` is the **only** caller that sets it, gated on the config
   toggle in §9. `diagnostics.rs`, `code_actions.rs`, `inlay_hints.rs` and
   `code_lens.rs` leave it `None` — which is how **FR-010 becomes structural**:
   those surfaces cannot reach deps.dev, because they are never handed a client.
4. `Ecosystem::generate_hover`'s default impl (ecosystem.rs:524-544) is
   untouched, so the two ecosystem crates that override it
   (`deps-github-actions`, `deps-nuget`) inherit the feature for free the moment
   they call `lsp_generate_hover`.

**Latency: spawn-and-warm, not a bare `join!`** (critic S1). The earlier claim
that the 2 deps.dev round-trips "overlap the registry fetch and disappear from
the common case" was **inverted**: `lifecycle.rs:1092-1095` prefetches
`get_versions_from` for every dependency at document open, so hover's registry
fetch is normally a warm `HttpCache` entry hit taking ~0 ms. deps.dev is
therefore the hover's critical path in the *common* case, and a bare `join!`
waits for it — adding up to the full budget to a hover that would otherwise
return in milliseconds. `deps-nuget` compounds it, adding its own fetch *after*
`lsp_generate_hover` (deps-nuget/src/ecosystem.rs:203-221).

The fetch therefore runs in a **detached `tokio::spawn`**, and hover awaits that
`JoinHandle` under `DEPS_DEV_TOTAL_BUDGET` (700 ms):

- Under budget → the section renders on this hover.
- Over budget → hover returns **immediately** with the section omitted (FR-006
  satisfied: the ceiling on added latency is the budget, and nothing else in
  the hover is touched), **while the spawned task keeps running to completion
  and writes the memo**. The next hover on that dependency is a memo hit and
  renders instantly.
- This is what `.claude/rules/rust-code.md` already asks for in the LSP layer:
  "Hover and completion responses must return quickly; delegate registry
  fetches to background tasks with caching." The detached task is that
  delegation; the memo is that caching.

The registry fetch and the spawn are still started together, so a cold registry
fetch overlaps rather than stacks. `Arc<DepsDevClient>` is cloned into the task;
a hover cancelled by the editor drops the handle but not the task, so the warm
memo survives cancellation.

Gating — the future is not spawned at all unless **all** of: `versions.trust`
is `Some`, `resolvable`, `versions.ecosystem` maps through §7's
`deps_dev_system` to `Some`, and an in-use version resolves. Checking the
mapping *before* spawning is what makes SC-004 ("zero requests for
Composer/Dart/Swift") hold with no HTTP mock reached at all.

Version source: `in_use_version(..)` / `concrete_pin_version(requirement,
ecosystem)` (`lsp_helpers/in_use_version.rs:172,294`) — never the latest
available version, because FR-004's provenance claim is version-specific and
attaching another version's provenance to this dependency would be a false
statement. No in-use version → no signal at all (D7/O1).

**Two version-resolution paths coexist, deliberately** (critic M6).
hover.rs:133-140 already computes and renders `versions.resolved`; the trust
signal uses `in_use_version`, which adds the `concrete_pin_version` fallback.
They can disagree: a Cargo `=1.2.3` with no lockfile renders no in-use version
line but *does* report provenance for `1.2.3`. That is the correct behaviour on
both sides — the rendered line reflects the lockfile, the trust signal reflects
what will actually be built — and the wider fallback is precisely what keeps
D7's gate from silencing lockfile-less workspaces. Not unified on purpose;
noted so a reviewer does not read it as an inconsistency.

**Required refactor in a dense function** (also M6): the in-use-version
computation and `normalized_name` (hover.rs:131) currently sit *below* the
registry fetch at hover.rs:91 and must be hoisted above it to build the gate.
Small, but it moves code in `generate_hover`'s most comment-dense region — the
developer should hoist only these two and leave the surrounding ordering
(config snapshot before shard guard, etc.) untouched.
- Rendering: a new `push_trust_signal_hover_section(&mut markdown,
  Option<&SupplyChainTrustSignal>)` beside the existing
  `push_deprecation_hover_section` / `push_vulnerability_hover_section`
  (hover.rs:447,484), called immediately after them (hover.rs:322-323) and
  before `**Recent versions**` — grouping all package/version context together,
  above the version list.

Format: **one line, no `###` header** — matching the spec's Goal
("`OpenSSF Scorecard: 7.2/10 · SLSA provenance: verified`") and deliberately
lighter than the deprecation/advisory sections, which carry actual warnings.
FR-012's informational-only stance is carried by the visual weight too, so no
severity language, no ⚠️.

```
🔐 **Supply chain**: OpenSSF Scorecard `8.5`/10 · SLSA provenance: verified
```

and, when the chosen SOURCE_REPO relation was `UNVERIFIED_METADATA`:

```
🔐 **Supply chain**: OpenSSF Scorecard `8.5`/10 *(self-reported repo)* · SLSA provenance: none found
```

- Score via `markdown_code_span`; `/10` outside the span.
- `*(self-reported repo)*` renders immediately after the score whenever
  `scorecard.self_reported` — one conditional, no extra data. Required, not
  cosmetic (spec §6, O5): the repository behind an `UNVERIFIED_METADATA`
  relation is claimed by the package's own metadata, so an unmarked score
  invites a hostile package to borrow a reputable repo's reputation. An
  attested relation renders no marker at all, which is what makes the marked
  case legible as the weaker claim.
- Provenance wording: `verified` / `attested but unverified` / `none found`.
  Omitted when `provenance == None` (query never made or failed) — FR-004's
  "we didn't check" vs "we checked and found nothing" distinction lands exactly
  on `Option<ProvenanceStatus>` vs `ProvenanceStatus::None`.
- Scorecard half omitted when `scorecard == None`; the `·` separator only
  appears between two present halves.
- **No third-party string reaches the rendered line at all** now that `date`
  and `project_id` are dropped (§3): every token is either a fixed literal or
  the `f32` score, so `escape_markdown` has nothing to guard here. Should a
  future revision re-add either field, it must go through `escape_markdown`
  like every other registry-sourced string in `hover.rs`.
- **No hyperlink** in v1: a link would splice a third-party-controlled id into
  a URL rendered in the editor, and the score itself is the payload. Additive
  later if wanted.
- `versions.offline` (hover.rs:416-418): `ensure_online` already blocks the
  fetch, so the section self-omits. The existing offline footer text mentions
  "version and vulnerability data" only — leave it; rewording it is a
  user-visible string change outside this spec.

## 9. Configuration

`DepsConfig` (config.rs:35) gains `#[serde(default)] pub supply_chain:
SupplyChainConfig`, holding `#[serde(default = "default_true")] pub enabled:
bool`, shaped exactly like `FreshnessConfig` (config.rs:554-563).
`handlers/hover.rs` reads it in the same snapshot that already reads
`freshness`/`offline` (hover.rs:29-32) and passes `.with_trust(..)` only when
enabled.

The spec has no FR for this (§10). Justification: this is the first feature to
send package names to a **third party that is not the package's own registry**,
two requests per hover. Every comparable signal in this server
(`vulnerabilities_enabled`) has an off switch, and a user on a locked-down
network needs one that is not "go fully offline".

## 10. Spec deviations needing lead sign-off

| # | Deviation | Why | If rejected |
|---|-----------|-----|-------------|
| D1 | FR-007/NFR-002 amended: `HttpCache` for transport, TTL memo for caching (§6) | deps.dev sends no validators; the spec's "a 304 avoids re-transferring the body" premise is false for this API | Every hover costs 2 full-body fetches; NFR-001's conservative-treatment goal is not met |
| D2 | **SC-005 retired** and replaced: assert "second `trust_signal` within TTL issues zero HTTP requests" (mockito hit count) | No `ETag` ⇒ no 304 path ⇒ the criterion can never pass | SC-005 stays permanently red |
| D3 | `provenance_verified: Option<bool>` → `Option<ProvenanceStatus>` (3-state) | Live entries carry `verified: bool`; the 2-state model prints "verified" for unverified attestations — a false trust claim | Implement spec-literal; log the false-positive as a known issue |
| D4 | `ScorecardCheck`, `checks[]`, `scorecard.version` dropped from the model (§3) | FR-003 mandates only `overallScore`; parsing ~20 checks to render none is unused surface | Parse and store them unrendered; expect a clippy/review dead-code flag |
| D5 | FR-002's SOURCE_REPO pick is ranked by `relation_provenance` (§5), and an unattested pick is disclosed in hover (§8) | Multiple SOURCE_REPO entries exist live; FR-002 assumes one, and the unranked pick inherits a spoofable Scorecard | First-match wins; spoofing residual stays unmitigated |
| D6 | Config toggle added (§9) | No FR covers it; third-party egress needs an off switch | Ship always-on |
| D7 | Signal gated on a concrete in-use version (§8) | FR-004's provenance claim is version-specific | See open question O1 |
| D8 | Gradle and Deno-`npm:` excluded (§7) | FR-001 enumerates 7 ecosystems, Gradle is not among them | Add two one-line overrides |

None of these need a *user* decision, and the spec's §8 "Ask First" item
(net_policy change) **does not fire** — see §6.

### Revisions after critique (all within D1-D8, no new deviation)

| Finding | Change | Section |
|---------|--------|---------|
| S1 | Detached `tokio::spawn` + 700 ms `DEPS_DEV_TOTAL_BUDGET`, replacing the bare `join!`; 400 ms per call | §4, §8, §11 |
| S2 | Already closed before the critique landed (commit 3a8e37c8) — `ScorecardSummary.self_reported` + render branch + test | §3, §5, §8, §12 |
| S3 | `overallScore` is `Option<f32>` with no serde default; no score ⇒ no Scorecard half | §3 |
| S4 | `DepsDevNaming` **dropped**; exhaustive `match EcosystemId` with no `_` arm | §7, §11 |
| S5 | Typed `MemoKey` struct instead of a `\0`-joined string | §4 |
| S6 | Eviction is new code modelled on `evict_release_dates_if_full`, not a reused helper | §6 |
| M1 | 404 memoized at the 1 h TTL as a definitive negative; `MemoEntry` holds the outcome | §4 |
| M2 | Second memo keyed by validated project key | §6 |
| M3 | net_policy mechanism description corrected (classifier runs on resolved addresses) | §6 |
| M4 | Concrete host-shape rule; non-ASCII over-rejection stated as intentional | §5 |
| M5 | `urlencoding` is a 3-line manifest change | §2 |
| M6 | Two version paths documented as deliberate; hoist refactor named | §8 |
| M8 | `ScorecardSummary.date`/`.project_id` dropped as unrendered | §3 |

M7 is spec/plan drift in `spec.md` (NFR-002's retired premise at :322-325 and
:341, `RelatedProject.project_key` at :261, `scorecard` at :264) — the lead's to
reconcile, not this plan's.

## 11. Alternatives considered

- **Prefetch all dependencies in `lifecycle.rs`, OSV-style, and pass a map via
  `VersionData`.** Rejected: OSV batches N packages into one POST, deps.dev
  needs 2 sequential GETs *per package* — a 200-dependency manifest becomes 400
  requests on open, nearly all for dependencies never hovered. Directly against
  NFR-001. The lazy per-hover fetch is 2 requests for the one dependency the
  user actually asked about.
- **Fetch in `handlers/hover.rs` and pass the finished
  `Option<&SupplyChainTrustSignal>` through `VersionData`.** Purer (no
  capability in a data struct, FR-010 still structural) but forces the fetch to
  *precede* `generate_hover`, so it cannot be spawned-and-abandoned the way §8
  needs — the handler would have to block on it before hover text exists at
  all — and it duplicates the position→dependency lookup (hover.rs:60-66) in
  the handler. Latency lost the tie.
- **A bare `tokio::join!` of the fetch with the registry fetch** — this plan's
  original §8, **reversed** after critic S1: `lifecycle.rs` prefetches the
  registry data, so there is normally no slow sibling future to hide behind and
  `join!` just adds the deps.dev latency to every hover. §8's spawn-and-warm
  keeps the overlap for the cold case and adds a hard ceiling for the warm one.
- **Fire-and-forget with no await at all** (always render the section from the
  memo only, never on the first hover). Bounds latency perfectly but a signal
  that appears only on the *second* hover of a dependency reads as a bug.
  Spawn-and-warm is the same mechanism with a 700 ms window to catch the common
  case on the first hover.
- **New parameter on `Ecosystem::generate_hover` / `lsp_generate_hover`.**
  Only 3 files override it, so the ripple is small — but `VersionData` already
  exists as the context bag for exactly this and needs no signature churn.
- **A `DepsDevNaming` concern trait on `EcosystemFormatter`** — this plan's
  original choice, **reversed** after critic S4 priced the supertrait ripple at
  55 impl sites across 27 files including 8 doc-tests. The rejection reason
  given here originally ("a central match lets a new ecosystem silently default
  to some arm") was simply wrong: an exhaustive match with no `_` arm turns a
  new ecosystem into a compile error, which is *stronger* than a `None` trait
  default. See §7.
- **Two methods on the existing `PackageNaming` trait** (critic's own
  suggested fix for S4 — zero new impl blocks, since `PackageNaming` is already
  a supertrait). Rejected in favour of §7's function: it still adds
  per-ecosystem extension points that no ecosystem needs, and it puts
  third-party-API naming inside the trait that owns *internal* normalization
  and validation. §7's match needs neither.
- **Entry-cached `get_cached_trusted_origin`** rather than transport-only.
  Rejected per §6: double-caching, and it evicts reusable registry bodies.
- **Computing the aggregate from `checks[]`.** Explicitly forbidden by FR-003.

## 12. Testing

- `mockito`, per `.claude/rules/testing.md`, against `DepsDevClient::for_test`.
- Fixtures from the live bodies probed in §1: `npm/express@4.19.2` (empty
  provenance arrays, two SOURCE_REPO relations), `npm/sigstore@2.3.1`
  (`verified: true`, an `SLSA_ATTESTATION` relation), and
  `projects/github.com%2Fexpressjs%2Fexpress` (`overallScore: 8.5`).
- Required cases: SC-001 score render; SC-002 both FR-004 branches **plus** the
  new `Unverified` branch (D3); SC-003 both endpoints failing leaves existing
  hover assertions byte-identical; SC-004 zero requests for Composer/Dart/Swift
  (`Mock::expect(0)`, which the `None` trait defaults make trivially true);
  D2's replacement for SC-005 (second call within TTL = zero requests);
  version-endpoint 200 + project-endpoint 500 → provenance rendered, Scorecard
  absent; malformed JSON and a `text/plain` 404 body both → `None`, no panic;
  a `scorecard` object with `overallScore` absent/null/`"x"` → Scorecard half
  omitted and **never** rendered as `0`/10 (S3); two `MemoKey`s differing only
  by a control character in `name`/`version` do not alias (S5); a 404 does not
  re-request within the hour and a 5xx does re-request after 90 s (M1); two
  packages sharing a project key issue **one** project call (M2); a hover whose
  fetch exceeds the budget renders with no trust section **and** leaves the memo
  warm so the next call is a hit (S1 — the load-bearing test for the whole
  latency design);
  both O5 branches — an `SLSA_ATTESTATION` relation renders no marker, an
  `UNVERIFIED_METADATA`-only one renders `*(self-reported repo)*`;
  project-key validation rejecting `github.com/../../etc` with zero requests;
  and the percent-encoding assertions for Go, Maven and scoped npm names.
- One `insta` snapshot for the hover line; snapshots live in
  `src/snapshots/` beside the module.
- §7's match removes the doc-test exposure the critic flagged under S4 — there
  are no new trait impls, so no rustdoc example needs updating.

## 12a. Answers to the critic's questions

1. **Added-latency budget (S1):** 700 ms is the ceiling on what a hover may
   *wait*, and because the fetch is detached it is a ceiling on the wait only —
   not on the fetch, which completes into the memo regardless. Practically the
   user-visible cost is ~2 RTTs on a cold memo and 0 afterwards. This does
   **not** reopen O2: the memo now absorbs the latency risk by construction
   (an over-budget hover still warms it), so teaching `HttpCache` a general
   `max-age` window would buy nothing here that the memo does not already buy,
   and the lead's scoping call stands.
2. **Disclosure carrier (S2):** `ScorecardSummary`, as already implemented. The
   disclosure qualifies *the Scorecard* specifically — which repository's score
   is being shown — and nothing about provenance, which is version-level and
   unaffected by the relation's provenance. Putting it on
   `SupplyChainTrustSignal` would let a signal carry `self_reported = true`
   with `scorecard: None`, a state that cannot mean anything. Naming: the
   critic proposed `relation_attested: bool`; the committed field is
   `self_reported: bool` — the same bit inverted, chosen because it names the
   user-visible concept and renders without a negation.
3. **Trait vs. `PackageNaming` (S4):** neither — see §7. Both options assume a
   per-ecosystem extension point, and no ecosystem needs one: the `system` is a
   function of `EcosystemId` alone and the name is `dep.name()` verbatim for all
   seven. The exhaustive match costs one function, zero impl blocks, zero
   doc-test edits, and makes a future ecosystem a compile error rather than a
   silent opt-out.

## 13. Open questions for the critic

> [!note] Resolved by the lead, 2026-09-03
> O1 — ship the in-use-version gate as written; revisit only if live testing
> shows it biting often. O2 — keep the transport + TTL-memo split scoped to
> this feature; teaching `HttpCache` a general `max-age` freshness window is a
> separate change. O3 — no age qualifier on the score for v1. O4 — keep
> "attested but unverified". O5 — **add the disclosure marker**, now folded
> into §3, §5, §8 and §12 and recorded as an edge case in `spec.md` §6.
> Listed below as written, for the critic to stress-test rather than
> re-litigate.

- **O1 — no in-use version.** §8 gates the whole signal on a concrete in-use
  version, so a manifest with no lockfile and no exact pin loses the Scorecard
  too, not just provenance. A third call
  (`GET /v3/systems/{system}/packages/{name}`) would recover the project key,
  at +1 round-trip and beyond the spec's two-call design. Recommendation: ship
  the gate, revisit if it bites in live testing.
- **O2 — memo vs. `HttpCache` layering.** Is the transport-only + TTL-memo
  split (§6) the right reading of FR-007's intent, or should the plan instead
  propose teaching `HttpCache` a `cache-control: max-age` freshness window,
  which would fix this class of API for every future caller? The latter is a
  materially larger, shared-code change with its own blast radius.
- **O3 — Scorecard staleness.** `scorecard.date` can be weeks old. Is
  rendering the bare score without an age qualifier acceptable, or should the
  line carry `*(as of <date>)*`? Cost is a few characters; the data is already
  parsed.
- **O4 — `Unverified` wording.** Is "attested but unverified" clear enough to a
  developer who has never met SLSA, or does that middle state read as noise
  next to a plain verified/none-found binary?
- **O5 — spoofable Scorecard.** §5 ranks the attested relation first, but an
  `UNVERIFIED_METADATA`-only package still shows a Scorecard for a repo it
  merely claims. Should the line mark that case (e.g. a trailing `?`), or is
  the spec's stated trust-deps.dev assumption sufficient?

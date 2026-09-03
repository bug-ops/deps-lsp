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
- `crates/deps-core/Cargo.toml`: `urlencoding` is currently
  `optional = true`, pulled in only by `test-util`. Production path-segment
  encoding needs it unconditionally — move it out of `dep:` optional (leaving
  it listed under `test-util` becomes unnecessary). One-line manifest change.

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
    overall_score: f32,                       // #[serde(default)]
    date:          String,                    // #[serde(default)]
}

// ---- public, ecosystem-agnostic (consumed by hover) ----
pub enum ProvenanceStatus { Verified, Unverified, None }

pub struct ScorecardSummary {
    pub overall_score: f32,     // 0.0..=10.0, clamped on parse
    pub date:          String,  // rendered escaped, never linked
    pub project_id:    String,  // validated SOURCE_REPO key, escaped on render
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

## 4. Client and the two-call sequence

```rust
pub struct DepsDevClient {
    cache:    Arc<HttpCache>,
    base_url: String,            // DEPS_DEV_API in prod; mockito URL in tests
    trusted_origin: String,      // format!("{base_url}/")
    memo:     DashMap<String, MemoEntry>,
}

impl DepsDevClient {
    pub fn new(cache: Arc<HttpCache>) -> Self;
    pub fn for_test(cache: Arc<HttpCache>, base_url: impl Into<String>) -> Self;

    /// Infallible. `None` == nothing to render.
    pub async fn trust_signal(
        &self, system: &str, name: &str, version: &str,
    ) -> Option<SupplyChainTrustSignal>;
}
```

`new`/`for_test`/`trusted_origin` copy `github::GithubTagsClient` (github.rs:180-218)
verbatim in shape — the established pattern for a shared third-party API client
in this crate.

Sequence inside `trust_signal`:

1. **Memo read.** Key `format!("{base_url}\0{system}\0{name}\0{version}")` —
   `base_url` in the key for the same reason `ReleaseDatesCache` includes
   `api_base` (github.rs:655-662): a mock-server hit must never serve a
   real-API read. Fresh entry → return its clone, **zero requests**.
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
4. **Memo write** (success TTL or error TTL), then return.

Strictly sequential — step 3's URL comes out of step 2's body — so a cold
hover costs exactly 2 round-trips. Each call gets its **own**
`tokio::time::timeout(DEPS_DEV_CALL_TIMEOUT)` (1.5s, sibling of
`RELEASE_DATES_FETCH_TIMEOUT = 2s`), not one timeout around the pair: a shared
budget would discard step 2's already-successful provenance whenever step 3
hangs, defeating the partial-failure requirement above.

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

This matters beyond determinism: `UNVERIFIED_METADATA` is derived from the
package's own manifest metadata, so a hostile package can point its repository
field at a reputable, high-scoring repo and **inherit that repo's Scorecard**
in the hover. The spec's Assumptions accept trusting deps.dev's relation as
given, so preferring the attested relation is the cheapest available mitigation
without new scope. Ranked as a residual risk for the security reviewer, not
solved by this plan.

**Project-key validation before URL interpolation.** `projectKey.id` is
third-party-controlled text spliced into a request path — the exact shape
`deps-npm`'s `evil/../secret` regression tests exist for. Before use: reject
unless every `/`-separated segment is non-empty, passes
`deps_core::lsp_helpers::is_dot_segment` as false, and contains only
`[A-Za-z0-9._-]`; require a host-like first segment and at least two segments.
Then percent-encode the **whole key as one path segment** via
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
  **90 s** (`RELEASE_DATES_ERROR_TTL`'s value, for negative caching);
  `MAX_MEMO_ENTRIES = 512` with the percentage-eviction helper
  `github.rs`/`osv/mod.rs` both already use. Refreshing an existing key skips
  eviction (github.rs:696-700).
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
trusted-origin endpoint", already true by construction. `net_policy`'s
classifier still runs on every hop through `hop_targets_blocked_host`
(cache.rs:179-186) and on the resolved address through the baseline resolver.
No new `HostClass` variant, no new policy tier, nothing to ask the user about.

**NFR-005** holds trivially: `extra_headers` is `&[]` at the one call site.

## 7. Ecosystem mapping — a new `DepsDevNaming` formatter trait

`formatter.rs` gains an eighth concern trait beside `OsvNaming`, added to the
`EcosystemFormatter` supertrait list and its blanket impl (formatter.rs:762-783):

```rust
pub trait DepsDevNaming: Send + Sync {
    /// deps.dev `system` segment, or `None` when deps.dev has no coverage.
    fn deps_dev_system(&self) -> Option<&'static str> { None }
    /// deps.dev's spelling of `dep`'s name, or `None` if unmappable.
    fn deps_dev_package_name(&self, _dep: &dyn Dependency) -> Option<String> { None }
}
```

Both defaults are `None`, so **FR-005 and FR-011 hold by construction**:
Composer, Dart, Swift, Deno and GitHub Actions need zero code and issue zero
requests — there is no ecosystem list to keep in sync and no way to forget one.
`OsvNaming` is the precedent for "third-party API naming lives on the
formatter, not in a central match" (formatter.rs:676-697), including its
rationale for taking `&dyn Dependency` rather than `&str`.

Overrides, one impl block per crate:

| Crate | `deps_dev_system` | Name |
|-------|-------------------|------|
| `deps-npm` | `"npm"` | as-is (scoped names encoded at the client) |
| `deps-cargo` | `"cargo"` | as-is |
| `deps-go` | `"go"` | as-is — deps.dev wants the `v` prefix `go.mod` already carries |
| `deps-maven` | `"maven"` | `group:artifact`; developer must confirm `Dependency::name()` already yields that form, else join it here |
| `deps-pypi` | `"pypi"` | as-is (server normalizes) |
| `deps-bundler` | `"rubygems"` | as-is |
| `deps-nuget` | `"nuget"` | as-is (server is case-insensitive) |

No `deps_dev_version` hook: Go is the only ecosystem whose namespace could
diverge and its manifests already carry `v`. Add one when a real divergence
appears.

Deliberately **not** covered, though both are one-line overrides:
`deps-gradle` (Maven coordinates — deps.dev's `maven` system covers them) and
Deno's `npm:` specifiers. FR-001 enumerates seven ecosystems and Gradle is not
among them; treating that as an omission rather than a boundary is the lead's
call (§10), and the follow-up is trivial either way.

## 8. Hover integration

**The signal is fetched inside `lsp_generate_hover`, concurrently with the
registry fetch, for the one hovered dependency only.**

Plumbing, chosen to require **no** signature change in any ecosystem crate:

1. `ServerState` (state.rs:471-514) gains `pub deps_dev: Arc<DepsDevClient>`
   beside `cache` and `osv`, built as
   `DepsDevClient::new(Arc::clone(&cache))`.
2. `VersionData` gains one field and builder:
   `pub trust: Option<&'a DepsDevClient>` / `with_trust(client)`. It already
   carries non-version context (`ecosystem`, `offline`), so this fits the type
   it actually is.
3. `handlers/hover.rs` is the **only** caller that sets it, gated on the config
   toggle in §9. `diagnostics.rs`, `code_actions.rs`, `inlay_hints.rs` and
   `code_lens.rs` leave it `None` — which is how **FR-010 becomes structural**:
   those surfaces cannot reach deps.dev, because they are never handed a client.
4. `Ecosystem::generate_hover`'s default impl (ecosystem.rs:524-544) is
   untouched, so the two ecosystem crates that override it
   (`deps-github-actions`, `deps-nuget`) inherit the feature for free the moment
   they call `lsp_generate_hover`.

Inside `hover.rs`:

- The current `let available_versions = if resolvable { … }` (hover.rs:91-98)
  becomes a `tokio::join!` of that same expression with the trust-signal
  future. Concurrency is the point: sequencing 2 deps.dev round-trips *after*
  the registry fetch would add their latency to every hover, and FR-006 forbids
  delaying other hover content. Joined, the 1.5s-per-call bound overlaps the
  registry fetch and disappears from the common case. `tokio::join!` of a
  fallible registry fetch with an infallible enrichment fetch is the pattern
  `deps-swift`'s `get_versions_with_release_dates` already uses.
- The trust future is `None` unless **all** of: `versions.trust.is_some()`,
  `resolvable`, `formatter.deps_dev_system()` is `Some`,
  `formatter.deps_dev_package_name(dep)` is `Some`, and an in-use version
  resolves. Version source: `in_use_version(..)` /
  `concrete_pin_version(requirement, ecosystem)`
  (`lsp_helpers/in_use_version.rs:172,294`) — never the latest available
  version, because FR-004's provenance claim is version-specific and attaching
  another version's provenance to this dependency would be a false statement.
  No in-use version → no signal at all (§10 open question).
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

- Score via `markdown_code_span`; `/10` outside the span.
- Provenance wording: `verified` / `attested but unverified` / `none found`.
  Omitted when `provenance == None` (query never made or failed) — FR-004's
  "we didn't check" vs "we checked and found nothing" distinction lands exactly
  on `Option<ProvenanceStatus>` vs `ProvenanceStatus::None`.
- Scorecard half omitted when `scorecard == None`; the `·` separator only
  appears between two present halves.
- Every third-party string (`date`, `project_id`) goes through
  `escape_markdown`. **No hyperlink** in v1: a link would splice a
  third-party-controlled id into a URL rendered in the editor, and the score
  itself is the payload. Additive later if wanted.
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
| D5 | FR-002's SOURCE_REPO pick is ranked by `relation_provenance` (§5) | Multiple SOURCE_REPO entries exist live; FR-002 assumes one, and the unranked pick inherits a spoofable Scorecard | First-match wins; spoofing residual stays unmitigated |
| D6 | Config toggle added (§9) | No FR covers it; third-party egress needs an off switch | Ship always-on |
| D7 | Signal gated on a concrete in-use version (§8) | FR-004's provenance claim is version-specific | See open question O1 |
| D8 | Gradle and Deno-`npm:` excluded (§7) | FR-001 enumerates 7 ecosystems, Gradle is not among them | Add two one-line overrides |

None of these need a *user* decision, and the spec's §8 "Ask First" item
(net_policy change) **does not fire** — see §6.

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
  *precede* `generate_hover`, serializing 2 round-trips ahead of the registry
  fetch instead of overlapping them, and duplicates the position→dependency
  lookup (hover.rs:60-66) in the handler. Latency lost the tie.
- **New parameter on `Ecosystem::generate_hover` / `lsp_generate_hover`.**
  Only 3 files override it, so the ripple is small — but `VersionData` already
  exists as the context bag for exactly this and needs no signature churn.
- **A central `match EcosystemId { … }` for the system mapping** instead of a
  formatter trait. Rejected: a new ecosystem silently defaults to *some* arm,
  whereas the trait's `None` default makes non-coverage the safe, automatic
  state (FR-005/FR-011) and keeps naming beside `OsvNaming`.
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
  project-key validation rejecting `github.com/../../etc` with zero requests;
  and the percent-encoding assertions for Go, Maven and scoped npm names.
- One `insta` snapshot for the hover line; snapshots live in
  `src/snapshots/` beside the module.

## 13. Open questions for the critic

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

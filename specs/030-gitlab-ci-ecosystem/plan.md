---
aliases:
  - GitLab CI Ecosystem Plan
tags:
  - sdd
  - plan
  - ecosystem/gitlab-ci
created: 2026-09-04
status: draft
related:
  - "[[030-gitlab-ci-ecosystem/spec]]"
  - "[[MOC-specs]]"
---

# Plan: GitLab CI/CD `include:` ecosystem (`crates/deps-gitlab-ci`)

> [!info] Scope
> Phase 2 (HOW) for [[030-gitlab-ci-ecosystem/spec]] / issue #466. Design only — no
> implementation. Every "Resolved Decision" in §9 of the spec is taken as given; this
> document turns them into module/type/wiring decisions.
>
> **Revision 2 (2026-09-04)** — reworked after an adversarial design review. Six structural
> changes from revision 1, each recorded inline at the section it affects: host routing moved
> out of `PackageName` into `DependencySource` (§3), `component:` re-pointed from tags to
> releases (§5), a two-level bound on host fan-out (§4.6), the token allowlist changed from a
> union to a replacement (§4.5), an honest statement of what a live config change can and
> cannot do (§4.5), and the security-hardened parser scaffolding extracted to `deps-core`
> rather than forked (§6).
>
> **Revision 3 (2026-09-04)** — second adversarial pass; all revision-2 changes held, and the
> two remaining edges of the §3 routing change are closed. The source-**unaware** `Registry`
> methods are now specified as unconditional `PackageNotFound` (never a host guess) with a
> source-aware completion path so version completions survive (§7a, §8.1); the config handle
> in `EcosystemRuntime` is a feature-agnostic raw `String`, with host validation relocated
> into this crate (§4.5, §8.3); the cap-refused route has exactly one user-visible outcome
> (§3.2/§4.6); the hover divergence is narrowed to `component:` only (§8.2); and the
> pagination-truncation warning keeps its cap parameter (§4.4).

## 1. Reference precedent

Closest existing analogue: `crates/deps-github-actions` (YAML manifest, non-package-manager,
git-tags datasource, token-gated API, shipped 2026-09-02). This plan mirrors its module
split, trait wiring, and test shape.

Two structural differences drive everything else:

1. **The target host is per-reference, not a compile-time constant** (NFR-008). No shipped
   ecosystem resolves against a manifest-supplied host *except* through the
   `DependencySource::AlternateRegistry` routing mechanism — which is therefore the
   mechanism this crate uses (§3, §4.6).
2. **The two include kinds have two different datasources.** A `project:` + `ref:` pin is a
   plain git ref, resolved from `/repository/tags`. A `component:` pin resolves against
   *published releases* — in the CI/CD Catalog a component version **is** a project Release,
   and a tag with no release is not a usable component version (spec FR-004/FR-007).

Read before implementing: `crates/deps-github-actions/src/{parser,registry,ecosystem,formatter,types}.rs`,
`crates/deps-core/src/github.rs`, `crates/deps-core/src/net_policy.rs`,
`crates/deps-core/src/registry.rs` (the `get_versions_from` / `get_latest_matching_from`
docs), `crates/deps-core/src/completion.rs` (`complete_versions_generic`, §7a.1),
`crates/deps-go/src/{registry.rs,ecosystem.rs}` (the closest routing precedent:
`register_chain` + `alternates` + `MAX_ALTERNATE_REGISTRIES`),
`crates/deps-nuget/src/registry.rs` lines 25-118 (`digest_salt`, `own_auth_digest`,
`origin_of`).

## 2. Crate layout

New workspace member `crates/deps-gitlab-ci` (`deps_gitlab_ci`), same shape as
`deps-github-actions`:

| File | Responsibility |
|---|---|
| `lib.rs` | Module decls, `pub use` re-exports, `is_valid_gitlab_coordinate`, diagnostic-code constants, crate-level pin-contract table (mirroring `deps-github-actions/src/lib.rs`'s) |
| `types.rs` | `GitlabCiDependency`, `IncludeKind`, `EndpointKind`, `PinStyle`, `HostRef`, `GitlabRoute`, `GitlabCiVersion`, `GitlabCiParseResult` |
| `host.rs` | `GitlabHost` (validated host newtype), `GitlabInstanceHost` (live-updatable config handle), the token-host rule |
| `parser.rs` | `parse_gitlab_ci_yaml` — event-driven `yaml-rust2` receiver over `include:` |
| `client.rs` | `GitlabApiClient` — per-host, `PRIVATE-TOKEN`-authenticated tags **and** releases fetch |
| `registry.rs` | `GitlabCiRegistry` — `deps_core::Registry` impl, route table, per-host rate-limit gate, version index |
| `component.rs` | `component:` pin classification + release-name/partial-semver resolution |
| `ecosystem.rs` | `GitlabCiEcosystem` — `deps_core::Ecosystem` impl |
| `formatter.rs` | `GitlabCiFormatter` — the six `EcosystemFormatter` sub-traits |
| `README.md` | Required; every crate has one |

**`GitlabApiClient` lives in this crate, not `deps-core`.** `deps_core::github` exists only
because two crates (`deps-swift`, `deps-github-actions`) share it verbatim (#472). GitLab has
exactly one consumer; promoting it to `deps-core` now is premature abstraction
(`.claude/rules/rust-code.md`, MVP rule). Promote only if a second GitLab-backed ecosystem
appears. The *ecosystem-neutral* pieces it needs — pagination, YAML span plumbing — do move
to `deps-core` (§4.4, §6), because those already have two consumers each.

## 3. Data types and routing

> [!important] Revision 2 — routing moved out of `PackageName`
> Revision 1 encoded the host *inside* the dependency name for `component:` and omitted it
> for `project:`. That cannot work: `Registry::get_versions` receives only a `&PackageName`
> (`deps-core/src/registry.rs:84`), and a 3-segment name `a/b/c` is ambiguous between
> "host `a` + project `b/c`" and "host-less subgroup project `a/b/c`" — GitLab group paths
> legally contain dots, so no "first segment looks like a hostname" heuristic is sound. The
> registry would have no way to know which host to fetch from.
>
> The host now travels in `DependencySource`, via the mechanism the codebase already uses for
> exactly this: `Registry::get_versions_from(name, source, freshness)` +
> `DependencySource::AlternateRegistry { index }`. Its three real call sites — the background
> fetch loop (`deps-lsp/src/document/lifecycle.rs:1254`), hover
> (`deps-core/src/lsp_helpers/hover.rs:123`) and code actions
> (`deps-core/src/lsp_helpers/code_actions.rs:583`) — already route through it for every
> ecosystem, so no call site changes.

```
enum IncludeKind  { Project, Component }
enum EndpointKind { Tags, Releases }        // Project -> Tags, Component -> Releases

enum HostRef {
    Literal(GitlabHost),   // validated + policy-gated (§4.1); from a `component:` prefix
                           // or from `registries.gitlab_instance_host`
    Unresolved(String),    // "$CI_SERVER_FQDN" / any CI-time variable, with the setting unset
}

struct GitlabRoute { origin: String, endpoint: EndpointKind }

enum PinStyle {
    Sha,      // 40-hex commit
    Tag,      // exact published tag / release name
    Branch,   // honest-unknown: not a SHA, not an exact tag, not partial semver
    Latest,   // literal `~latest` (component: only)
    Partial,  // `1` / `1.2` (component: only)
}
```

`GitlabCiDependency` mirrors `GithubActionsDependency` field-for-field where the concepts
coincide (`name`, `name_range`, `version_req`, `version_range`, `version_literal`, `source`,
`is_plain_scalar`), plus `kind: IncludeKind`, `host: HostRef`, `pin: Option<PinStyle>`,
`project_path: String` (the bare `org/sub/proj`, kept for URL construction and for the
registry's own use).

### 3.1 `name` — host-qualified, for cache-key correctness

`name` is a *display and cache* coordinate, never a routing instruction:

| Include kind | Host known | `name` |
|---|---|---|
| `project:` | yes | `{host}/{project_path}` |
| `component:` | yes | `{host}/{project_path}/{component_name}` |
| either | no | the path alone, without a host prefix |

Two consequences, both deliberate:

- **NFR-007 is satisfied structurally.** Every name-keyed structure — `DocumentState`'s
  `cached_versions`/`resolved_versions`, the crate's version index (§7), and every
  `PackageName`-keyed lookup in `deps-core` — is keyed per instance automatically. Revision 1
  omitted the host from the `project:` key and so contradicted its own NFR-007 rationale:
  after a `gitlab_instance_host` change, instance A's tags would have been served for
  instance B. (`HttpCache` keys on the full URL and was always safe; the in-crate index was
  not.)
- **The `component:` name keeps its final component segment**, unlike revision 1. Dropping it
  would collide with a `project:` include of the same project on the same host — one
  `PackageName`, two different sources (a `Tags` route vs. a `Releases` route). The
  consequence is *degradation, not wrong data*: `collect_fetch_targets`
  (`deps-lsp/src/document/lifecycle.rs:100-116`) detects two distinct sources under one
  `PackageName`, `warn!`s, and removes the name from the fetch set entirely — **both**
  occurrences lose version data, not just one. Keeping the segment avoids that. The
  de-duplication revision 1 wanted is preserved anyway at the transport layer: several
  components of one project produce one distinct request URL, which `HttpCache` serves once.

  The segment does not eliminate collisions entirely. `project: org/sub/comp` and
  `component: {host}/org/sub/comp` on the same host still produce the identical name
  `{host}/org/sub/comp`. That case is *safe* — the two sources differ, so `lifecycle.rs`
  drops both and logs — but it is a real (if contrived) loss of version data and belongs in
  the parser's doc comment as a known limitation, not as a surprise in a bug report.

A dependency whose host is `Unresolved` is never fetched (§3.2), so its un-prefixed name
never reaches a registry or a URL.

### 3.2 `source` — the routing channel

| Situation | `DependencySource` | Effect |
|---|---|---|
| Host known, route registered | `AlternateRegistry { index: route_key, mirrors_crates_io: false }` | Routed by `GitlabCiRegistry::get_versions_from` / `get_latest_matching_from` to `(host, endpoint)` |
| Host `Unresolved` (FR-012), or the §4.6 cap refused registration | `CustomRegistry { url: raw_host_expr }` | `can_resolve_source` is `false` by default, so the fetch loop skips it (`lifecycle.rs:92`), hover skips the registry lookup (`hover.rs:90`), and the unknown-package rule's final arm emits **nothing** (`diagnostics.rs:1023`, R5 arm 6). Exactly FR-012's skip, with no bespoke gate |

`route_key = deps_core::hash_routing_key("gitlab", [origin, endpoint_kind_str].into_iter())`
(`deps-core/src/registry.rs:380`, the helper #584 extracted for precisely this — note it takes
an `Iterator`, not an array) — an opaque key, not a URL: `AlternateRegistry.index` is already
documented as a resolved routing handle, and `deps-go`/`deps-pypi`/`deps-nuget` all put a
hashed chain key there rather than a bare URL.

> [!important] Revision 3 — the cap-refused route has one outcome, not two
> Revision 2 gave a dependency whose route the §4.6 process-wide cap refused two different
> user-visible behaviors: the table above says `CustomRegistry` (silent skip), §4.6 said
> "degrades to `DepsError::PackageNotFound`". Those are not the same thing — with
> `can_resolve_source` true, a `PackageNotFound` is a *fetch failure*, and
> `apply_unknown_package_rule` (`diagnostics.rs:988-1010`, R5 arm 3) turns it into a
> **"Registry lookup failed for '{name}'"** diagnostic, not silence.
>
> **The table above is authoritative.** It matches FR-012's informational tone, and a
> user-visible "lookup failed" for a purely internal capacity limit would be misleading.
> Because the parser sets `source` before `parse_manifest` registers routes, this requires an
> explicit **post-registration downgrade pass** in `GitlabCiEcosystem::parse_manifest`
> (§4.6/§8.1): after `register_routes` reports which routes it refused, every dependency
> carrying a refused `route_key` is rewritten to `CustomRegistry { url: origin }` and its
> `HostRef` to `Unresolved`, so the FR-012 informational diagnostic covers it. This is a
> mutation of the parse result the ecosystem already owns, before it is returned.
>
> `get_versions_from`'s `PackageNotFound`-for-an-unregistered-index arm (§7a) stays, purely
> as the defensive fallback — after the downgrade pass no dependency should ever reach it,
> and routes are never removed once registered.

`mirrors_crates_io: false` always (a Cargo-only concept). Two stated consequences of using
`AlternateRegistry` for every resolvable GitLab CI dependency, both correct here and both
previously unstated:

- `SourcePolicy::source_is_public_registry_content` stays `false`, which suppresses OSV
  lookups and deps.dev trust signals. **Intended**: a git tag has neither an OSV coordinate
  nor a deps.dev package identity, so those lookups would be meaningless by name.
- `SourcePolicy::can_resolve_source` **must** be overridden to accept `AlternateRegistry`
  (the standard override every routing ecosystem already writes — `deps-npm`, `deps-pypi`,
  `deps-go`, `deps-nuget`). It stays a pure function of `source`, reading no live state; see
  §4.5's live-update note for why a state-reading predicate here would be actively harmful.

`GitlabCiVersion { version, sha, prerelease, published_at }` — built with
`deps_core::impl_version!`, `RemovalStatus::Available` unconditionally (GitLab exposes no
yank signal), `reports_yanked() -> false`. `published_at` is `Some(released_at)` for the
releases endpoint (free — it is in the same response) and `None` for tags: a tag's only date
is its *commit* date, which is not a publish date and would misreport freshness.

## 4. `GitlabApiClient`

### 4.1 Shape

```
pub struct GitlabApiClient {
    cache: Arc<HttpCache>,
    token: Option<AuthToken>,               // Redacted; PRIVATE-TOKEN header value
    policy: Arc<RegistryAccessPolicy>,      // live-updatable, threaded from ServerState
    instance_host: Arc<GitlabInstanceHost>, // live-updatable; §4.5
}
```

Field-level comparison against `deps_core::github::GithubTagsClient`:

| `GithubTagsClient` | `GitlabApiClient` | Why |
|---|---|---|
| `api_base: String` (const `GITHUB_API`) | **removed** — the host is a per-call `&GitlabHost` argument | NFR-008 |
| `trusted_origin: String` (precomputed once) | derived per call from the `GitlabHost` newtype, which caches its own serialized origin | same, one origin per host not per client |
| `auth_headers: Vec<(HeaderName, AuthToken)>` with `AUTHORIZATION: Bearer …` | `token: Option<AuthToken>` attached as `PRIVATE-TOKEN`, and only to the token host (§4.5) | NFR-006 |
| `has_token: bool` | same (derived from `token.is_some()`) | rate-limit messaging (FR-014) |
| — | `policy`, `instance_host` | the host comes from file content; §4.2, §4.5 |

`AuthToken` is a crate-local copy of `deps_core::github`'s pattern (a thin `secret::Redacted`
wrapper whose `Debug` prints `AuthToken(***)`). It is ~15 lines and its GitHub twin is
module-private; do **not** widen `deps_core::github`'s visibility for it.

`GitlabHost` is a validated newtype produced once per unique host:

```
GitlabHost::parse(raw_host, &policy) -> Result<GitlabHost, IndexUrlError>
```

implemented over **`deps_core::net_policy::validate_index_url(&format!("https://{raw}"),
raw, "gitlab-ci", PolicyGate::Enforce(&policy))`** (`net_policy.rs:582`) — the same gate
`deps-cargo`, `deps-npm` and `deps-pypi` already use for manifest-declared hosts. It supplies
https-only, userinfo rejection, and `HostClass` blocking (loopback / link-local / private /
cloud-metadata) for a host string that comes straight out of a checked-in file.

**`parse` additionally round-trips the host.** `format!("https://{raw}")` will happily absorb
a `raw` containing `:`, `?`, `#`, `@` or `/` — `gitlab.com?x` parses to a clean
`https://gitlab.com` origin while the caller still believes the host is `gitlab.com?x`.
`parse` therefore rejects any `raw` containing those characters *before* formatting, and
asserts `url.host_str() == Some(raw_lowercased)` afterwards. `GitlabHost` stores both the
verified host and `url.origin().ascii_serialization()`, computed once: the origin is needed
three times over (the token-host comparison, `get_cached_pinned_with_headers`'s
`trusted_origin` argument, and the `auth_id` digest) and re-deriving it per call is how
normalization bugs enter.

### 4.2 Fetch paths — pinned tier, not trusted-origin tier

```
Tags      GET https://{host}/api/v4/projects/{enc}/repository/tags
              ?per_page=100&page={n}&order_by=version&sort=desc
Releases  GET https://{host}/api/v4/projects/{enc}/releases
              ?per_page=100&page={n}
```

- `enc = urlencoding::encode(project_path)` (workspace dep, already present) collapses
  `org/sub/proj` into one `org%2Fsub%2Fproj` path segment — structurally closing the
  `..`-traversal class `deps_core::github::validate_owner_repo` guards against. Validate
  anyway (§4.3): the same value is reused for display URLs.
- Transport: **`HttpCache::get_cached_pinned_with_headers(url, origin, authenticated,
  auth_id, &[(PRIVATE_TOKEN, token)])`** (`cache.rs:1148`), *not*
  `get_cached_trusted_origin_with_headers` (its weaker sibling at `cache.rs:1102` — the two
  are adjacent, so cite by name when reading, not by line). Its own docs name it "the only sanctioned way to
  send a credential to a workspace-declared host" — it adds the connect-time
  resolved-address guard (#449/#455 DNS-rebinding TOCTOU) that the baseline tier does not,
  and namespaces the cache entry per policy. `GithubTagsClient` correctly uses the weaker
  tier because its origin is a compile-time constant; GitLab's is not.
- `auth_id`: a salted `u64` digest of `(origin, token_header_value)`, `None` when no token is
  attached. Copy `deps_nuget::registry::own_auth_digest`/`digest_salt` (`registry.rs:29-55`)
  rather than inventing one; `deps_core::hash_routing_key` is a *string* routing key and is
  the wrong helper here.
- **`order_by=version`, not `order_by=updated`.** GitLab's `updated` ordering sorts tags by
  *commit* date, so a backport tag cut from an old commit sorts old and can fall past the
  page cap — the same class of hazard `deps_core::github::MAX_TAG_PAGES`'s own doc comment
  documents for GitHub's lexicographic ordering. `version` (GitLab 16.0+) is the semantically
  correct choice. An older self-hosted instance answers an unknown `order_by` with `400`; on
  a `400` for the first page, retry that page once with no `order_by` parameter and log the
  degradation at `debug`. Record the reasoning on the crate's own page-cap constant.
- `/releases` has no `order_by=version`; its default ordering is by release date, which is
  adequate because the resolver sorts the parsed list itself (§5) and catalogs are small.

### 4.3 Project-path validation

`is_valid_gitlab_coordinate(&str) -> bool` — crate-local, **cannot reuse**
`deps_core::github::is_valid_github_identity` (that one hard-codes exactly two segments;
GitLab subgroups nest arbitrarily). Rules: 2..=N `/`-separated segments; each segment
non-empty and drawn from `[A-Za-z0-9._-]`; no segment is `.` or `..` (reuse
`deps_core::lsp_helpers::is_dot_segment`, `mod.rs:894` — the #357 precedent); the final
segment does not end in `.git` or `.atom`.

> [!note] Why one predicate covers both the bare path and the host-qualified name
> This is a **syntactic safety gate** — "can this string be spliced into a URL path without
> traversal or structural characters" — not a semantic classifier. It is deliberately not
> asked to decide whether the first segment is a hostname or a group, which is the question
> §3's revision-1 naming scheme could not answer. A hostname's character set is a subset of
> the segment charset, so `gitlab.com/org/proj` and `org/proj` both pass, and both are safe
> for the two uses that matter: the percent-encoded fetch path (built from `project_path`,
> never from `name`) and the display URL. Revision 1's `validate_package_name` was incoherent
> precisely because it was expected to double as a *meaning* gate.

It is shared by the fetch-URL gate and the formatter's display-URL gate, exactly as
`is_valid_github_identity` is, so the two cannot drift.

### 4.4 Pagination

`deps_core::github::paginate_tags` is not reusable as-is: its body calls `parse_tags_page`,
which deserializes `Vec<GithubTag>` (`commit.sha`) and recognizes GitHub's error-object
shape. GitLab returns `commit.id`, a different error object, and — for `/releases` — an
entirely different element type.

Extract the loop into a page-parser-generic
`deps_core::pagination::paginate_pages<T>(provider, ecosystem, name, max_pages, parse_page,
fetch_page)` and make `github::paginate_tags` a thin delegation to it with `parse_tags_page`.
That loop carries several hard-won review findings (ordered `buffered`, not
`buffer_unordered`; error mapping applied to the *outcome*, not inside the closure; bounded
overfetch) — copying it into a second crate would fork them.

Two details the extraction must not lose:

- `warn_if_pagination_truncated` (`github.rs:378-388`) already takes an `ecosystem: &str`
  naming the *caller* (`"Swift"`, `"GitHub Actions"`), but hardcodes the *provider* — "while
  **GitHub** reported more pages available" — in its text. It gains a second
  `provider: &'static str`; `paginate_tags` passes `"GitHub"` so its log line stays
  byte-identical, and GitLab passes `"GitLab"` instead of logging a GitHub message.
- **`max_pages` must be threaded into the warning too, not just into the loop.** The function
  reads `MAX_TAG_PAGES` twice — once as the fire condition (`page == MAX_TAG_PAGES`) and once
  as the `pages_fetched` field. Parameterizing only the loop leaves both reads pointing at
  GitHub's constant, so a `MAX_GITLAB_PAGES != 30` makes the warning fire on the wrong page
  or never fire at all — silently disabling the one observability signal this helper exists
  for. Final signature:
  `warn_if_pagination_truncated(provider, ecosystem, name, page, page_len, max_pages)`.
- `MAX_TAG_PAGES` (`github.rs:46`) stays where it is, with its GitHub-ordering-specific
  rationale intact; `max_pages` becomes a parameter and this crate passes its own
  `MAX_GITLAB_PAGES`, documented against `order_by=version` (§4.2) rather than against
  GitHub's lexicographic ordering.

This touches `deps-core`, `deps-github-actions` and `deps-swift`; keep the refactor
mechanical and in its own commit, with those crates' existing tests unchanged.

Page element types: `GitlabTag { name, commit: GitlabTagCommit { id } }` and
`GitlabRelease { tag_name, released_at, commit: GitlabTagCommit { id } }`, `#[serde(default)]`
at every nested level, same as `GithubTag`.

### 4.5 `registries.gitlab_instance_host`, and the one token host

Confirmed by the issue owner 2026-09-04 (spec FR-005a/FR-011a, §9 below). One new LSP setting
serves both purposes.

> [!important] Revision 3 — the shared handle is a raw `String`, validation lives here
> Revision 2 put `gitlab_instance_host: Arc<GitlabInstanceHost>` — a `deps-gitlab-ci` type —
> into `EcosystemRuntime`. That does not compile as designed. `EcosystemRuntime`
> (`deps-lsp/src/lib.rs:22-30`) is **un-`cfg`'d** and is built with plain struct literals in
> un-`cfg`'d code (`document/state.rs:534-537`, `lib.rs:382-385`); its two fields are
> deliberately feature-agnostic, and the very nuget precedent this plan cites chose a bare
> `Arc<AtomicBool>` *precisely* so the struct never holds a type from an `optional = true`
> crate. A `deps-gitlab-ci` type there would force `#[cfg(feature = "gitlab-ci")]` onto the
> field and onto every literal, and §2 forbids promoting this crate's types into `deps-core`.
>
> **The shared handle carries the raw configured string; all host semantics stay in this
> crate.** `EcosystemRuntime` gains
> `gitlab_instance_host: Arc<std::sync::RwLock<Option<String>>>` — `std` types only, no
> `#[cfg]`, `Debug + Clone` like the rest of the struct.

```
pub struct GitlabInstanceHost {
    raw: Arc<RwLock<Option<String>>>,      // shared with EcosystemRuntime / config.rs
    policy: Arc<RegistryAccessPolicy>,     // needed by GitlabHost::parse
    memo: RwLock<Option<(String, Option<GitlabHost>)>>,  // last (raw, parse outcome)
}
impl GitlabInstanceHost { fn get(&self) -> Option<GitlabHost>; }
```

`std::sync::RwLock` is correct because no read ever spans an `.await` (a `String` cannot use
an atomic, and `arc-swap` is not a workspace dependency). The `Arc<RegistryAccessPolicy>` is
already threaded into this crate's `with_context` constructor (§8.3), so no new plumbing.

**Setting** — `registries.gitlab_instance_host: String`, default `""` (unset).
`RegistriesConfig` is deliberately *not* under `DepsConfig`'s top-level
`deny_unknown_fields` (see that struct's own doc comment), so adding this field is
additive-safe. `config.rs` writes the raw value straight through (`""` ⇒ `None`); it performs
no host validation, because it must not depend on `deps-gitlab-ci`.

**Validation runs on read, not on write.** `get` compares the current raw string against
`memo`'s key; on a match it returns the memoized outcome, and otherwise it runs the same
`GitlabHost::parse` gate as a host read out of a manifest (§4.1) — https-only, no userinfo,
round-trip check, `HostClass` policy check — and memoizes the result. A value that fails is
**treated as unset** (`None`) exactly as before; only the *location* of the check moved.

Two consequences of relocating it, both deliberate:

- **The rejection is logged once per distinct invalid value, not per read.** The memo cell
  gives this for free: the `warn` fires only when a new raw string is parsed. Without it a
  single bad setting would flood the log on every hover, completion and diagnostic pass.
- **An invalid value is inert everywhere at once.** Because both effects below read through
  the same `get`, a rejected value can neither resolve a host nor become the token host —
  the security property of §9.2 does not depend on where validation happens, only on the fact
  that nothing but `get` ever produces a `GitlabHost` from configuration.

**Effect 1 — host resolution (FR-011a).** When set, it is the host that `project:` includes
and `$CI_SERVER_FQDN`-relative `component:` includes resolve against. When unset, both are
`HostRef::Unresolved` and take the §3.2 skip path plus the FR-012 informational diagnostic.

**Effect 2 — the token host (FR-005a).**

> [!danger] Revision 2 — replacement, not union
> Revision 1 defined the allowlist as `["gitlab.com"] ∪ {instance_host}`. That leaks: a user
> whose `GITLAB_TOKEN` is a PAT for `gitlab.mycorp.dev` would have that token attached to any
> `component:` include naming `gitlab.com` — a host any cloned repository can name in a
> checked-in file. A GitLab PAT is only ever valid for the instance that issued it, so the
> union buys nothing to trade against the leak.

The token host is therefore **exactly one host**:

```
token_host = instance_host.get().unwrap_or(GITLAB_COM)
```

`PRIVATE-TOKEN` is attached only when the target host's serialized origin equals
`token_host`'s. Every other host is still fetched — subject to `validate_index_url`'s
`HostClass` gate — but unauthenticated. Without this, opening any repository whose
`.gitlab-ci.yml` contains `include: - component: attacker.example/a/b/c@1.0` would send the
developer's `GITLAB_TOKEN` to `attacker.example`.

**Compare on the normalized origin, never the raw string.** The comparison runs against
`url::Url::origin().ascii_serialization()` of the already-parsed `GitlabHost`, following
`deps_nuget::registry::origin_of` (`registry.rs:77-88`, issue #561 C1). A raw string
comparison would be defeated by case (`GITLAB.COM`), a trailing dot (`gitlab.com.`), a suffix
lookalike (`gitlab.com.attacker.example`), or a punycode confusable.

**Cache-key consequence.** Because the same `(host, project)` pair can be fetched
authenticated or not, `auth_id` must be `None` for the unauthenticated case and
`Some(digest)` for the authenticated one (§4.2). That is what the digest is for: a response
fetched without the token can never be served back to a request that would have carried it,
or vice versa.

> [!warning] What a live configuration change actually does — SC-007b's limitation
> Revision 1 claimed `didChangeConfiguration` updates "take effect live". They do not, for
> the resolution half. `Server::did_change_configuration`
> (`crates/deps-lsp/src/server.rs:516-565`) updates the shared handles and fires
> `workspace/diagnostic/refresh`; it never re-parses an open document and never re-schedules
> a version fetch. Hover reads the *stored* `parse_result`
> (`crates/deps-lsp/src/handlers/hover.rs:52-64`), so it does not re-derive `HostRef` either.
> There is no re-parse-on-config-change mechanism anywhere in the server — the same gap
> applies today to `registries.workspace_registries` and
> `registries.nuget_user_profile_sources`.
>
> **Design decision: state the limitation, do not paper over it.** `HostRef` and `source` are
> decided at parse time; a document already open when the setting changes picks the change up
> on its next edit or reopen. The common case — the setting present in `initialize`'s
> settings payload, before any `didOpen` — is fully live. spec.md's SC-007b now says exactly
> this.
>
> **Rejected alternative: a live-reading `can_resolve_source`.** Making the formatter's
> predicate consult `instance_host` at call time would make the diagnostic refresh *worse*,
> not better: `apply_unknown_package_rule` (`deps-core/src/lsp_helpers/diagnostics.rs:953-1023`)
> emits `Unknown package '{name}'` on arm R5d whenever `can_resolve_source` is true and no
> version data has been fetched. Flipping the predicate true on a config change, with the
> background fetch still un-run, would replace the correct FR-012 informational diagnostic
> with a false "Unknown package" on every include in the file. The predicate stays a pure
> function of `source`.
>
> Closing the gap properly means a server-wide "re-parse open documents on
> `didChangeConfiguration`" facility that benefits three settings, not one. File it as a
> follow-up issue (`enhancement`, P3) referencing this section; it is out of scope here.

### 4.6 Bounding the host fan-out

> [!important] Revision 2 — new section
> `HttpCache::trusted_clients` is a `DashMap<(String, CacheTier), Transport>` with **no
> eviction** (`deps-core/src/cache.rs:756`), holding one full `reqwest::Client` per origin.
> Every existing caller passes an origin from a bounded set: a compile-time constant, or a
> chain registered under a `MAX_ALTERNATE_REGISTRIES = 256` cap
> (`deps-nuget/src/registry.rs:105`, mirrored in `deps-go`/`deps-npm`/`deps-pypi`). GitLab CI
> would otherwise be the first ecosystem to hand it an origin taken straight from
> per-document file content with no cap — a `.gitlab-ci.yml` naming N distinct `component:`
> hosts would create N clients and N DNS/TLS connects on a single `didOpen`.

Two bounds, at the two places the growth actually happens:

1. **Per document, at parse time:** `MAX_HOSTS_PER_DOCUMENT: usize = 8` distinct literal
   hosts. The parser tracks the distinct origins it has admitted for the current document;
   once at capacity, a further *new* host is logged once at `warn` (host redacted through
   `deps_core::net_policy::redact_userinfo`, value length only per the `warn_rejected_value`
   precedent) and its dependency is emitted with `HostRef::Unresolved` — i.e. it takes the
   §3.2 skip path and never reaches the transport at all. This is the bound that matters for
   the `didOpen` burst, and no process-wide cap can provide it.
2. **Process-wide, at registration:** `MAX_GITLAB_ROUTES: usize = 256` entries in
   `GitlabCiRegistry::routes`, mirroring `MAX_ALTERNATE_REGISTRIES` exactly, including its
   core semantics — at capacity a *new* route is simply never registered, and a dependency
   is **never** fetched against some other host as a consequence. Existing routes stay
   registered and idempotent.

   Where this ecosystem diverges from `MAX_ALTERNATE_REGISTRIES` is the *user-visible*
   outcome (§3.2's revision-3 note): `register_routes` returns the set of `route_key`s it
   refused, and `parse_manifest` downgrades every dependency carrying one to
   `CustomRegistry` + `HostRef::Unresolved` before returning the parse result. The
   capacity limit therefore surfaces as FR-012's informational diagnostic, not as a
   `PackageNotFound`-driven *"Registry lookup failed"*. `get_versions_from`'s
   unregistered-index arm still returns `DepsError::PackageNotFound` (§7a) — after the
   downgrade pass that arm is unreachable, and it exists only so an unregistered index can
   never silently become a fetch against a different route.

Since a route is `(origin, endpoint)`, 256 routes bound distinct origins at 256 — the same
ceiling `deps-nuget` already imposes on `trusted_clients` growth, so this ecosystem adds no
new class of unboundedness.

Registration mirrors `GoRegistry::register_chain` (`deps-go/src/registry.rs:306-330`) and is
driven from `GitlabCiEcosystem::parse_manifest` over `GitlabCiParseResult::routes`, exactly
as `deps-go` does at `ecosystem.rs:211` — the one point where a per-document parse and the
long-lived registry meet.

## 5. `component:` resolution (`component.rs`)

Layered on the shared client as a focused function, per spec §9.4 — **not** a second
`Registry` impl.

> [!important] Revision 2 — releases, not tags
> Revision 1 resolved `component:` pins against `/repository/tags` and deferred `/releases`
> to "freshness enrichment". That inverts the datasource. In the CI/CD Catalog a component
> version **is** a project Release; a tag with no release is not a resolvable component
> version. Resolving `~latest` or `1.2` against the raw tag list can therefore pick a tag
> that was never published, and FR-010's code action would then write a pin that breaks the
> user's pipeline. `/releases` is the identity source for this include kind and cannot be
> deferred. It also supplies `released_at` for free, so §9.3's separate freshness deferral
> now applies only to `project:`.

```
enum ComponentPin { Sha(String), Exact(String), Latest, Partial(semver::VersionReq) }
fn classify_component_pin(raw: &str) -> ComponentPin
fn resolve_component_pin(pin: &ComponentPin, releases: &[GitlabRelease]) -> Option<ConcreteVersion>
```

FR-007's documented priority order, applied against the one fetched **release** list:

1. **SHA** — `is_full_sha(raw)`; resolved for display via the `sha_to_tag` side of the version
   index (§7), never used for outdated comparison.
2. **Exact release** — `releases.iter().any(|r| r.tag_name == raw)`.
3. **Branch** — not observable from either endpoint. Anything that is neither a SHA, an exact
   release, `~latest`, nor partial-semver-shaped is classified `PinStyle::Branch` and treated
   as the honest-unknown (no version data, no outdated diagnostic), exactly as
   `deps-github-actions` treats a branch ref. Do **not** add a `/repository/branches` fetch
   for v1: it doubles the request cost against the NFR-002 budget to distinguish two cases
   that render identically.
4. **`~latest`** — highest non-prerelease semver-parseable release.
5. **Partial semver** — `semver::VersionReq::parse(&format!("~{normalized}"))`. **This one
   rule covers both forms** and answers spec §8's third "Ask First" item: `~1.2` desugars to
   `>=1.2.0, <1.3.0` (highest published `1.2.*`) and `~1` to `>=1.0.0, <2.0.0` (highest
   published `1.*.*`) — precisely GitLab's documented semantics, with zero hand-rolled
   comparison (`.claude/rules/rust-code.md`). `VersionReq::matches` already excludes
   prereleases unless the requirement itself carries one, matching GitLab's catalog behavior.

Two normalization rules, easy to get subtly wrong:

- Partial-*shape* recognition runs on `raw` after an optional `v`/`V` strip: 1 or 2
  dot-separated all-ASCII-digit segments. Reuse `deps_core::github::normalize_tag`.
- **Matching runs against `normalize_tag`'d release names, not raw ones.** Revision 1 applied
  `normalize_tag` only to pin-shape recognition, so a project tagging `v1.2.3` would have
  matched nothing for a `1.2` pin. Normalize both sides.

## 6. Parser (`parser.rs`)

Event-driven `yaml_rust2::parser::MarkedEventReceiver`, following
`deps-github-actions/src/parser.rs`'s structure. A YAML syntax error degrades to an empty
`ParseResult` (logged at `debug`), never a propagated error. `check_yaml_nesting_depth` /
`check_yaml_expansion` gate before any parsing.

### 6.1 Shared scaffolding — extract, do not fork

> [!important] Revision 2 — §4.4's own reasoning, applied consistently
> Revision 1 said to copy `deps-github-actions/src/parser.rs`'s scaffolding "wholesale". Those
> helpers are crate-private and carry that crate's S-1/S-2 security hardening; copying them is
> exactly the fork §4.4 refuses to make for `paginate_tags`. They are ecosystem-neutral text-
> and span-plumbing, so they move to `deps_core::lsp_helpers` — where their siblings
> `LineOffsetTable` (`mod.rs:617`), `is_dot_segment` (`mod.rs:894`), `warn_rejected_value`
> (`mod.rs:1117`) and `is_full_semver_shape` (`lsp_helpers/in_use_version.rs:93` — same
> module tree, a different file) already live — and become `pub`:

| Item | Current location | Carries |
|---|---|---|
| `CharOffsets` | `deps-github-actions/src/parser.rs:60` | yaml-rust2's marker is a **char** index despite its docs |
| `locate_value_span` | `parser.rs:104` | the trimmed-span re-anchoring (security S-1) |
| `MAX_FALLBACK_SCAN_BYTES` | `parser.rs:93` | the bounded fallback scan (security S-2) |
| `is_full_sha` | `parser.rs:34` | — |
| `is_tag_shaped` | `parser.rs:42` | — |
| `match_v_prefix_style` | `deps-github-actions/src/formatter.rs:32` | §8.2 reuses it by name |

`deps-github-actions` then imports them instead of defining them; its existing tests move with
them where they test the helper rather than the workflow parser. Same rule as §4.4: mechanical,
its own commit, `deps-github-actions` stays green.

### 6.2 The receiver's state machine

Instead of GHA's "a `uses` key with no `with:` ancestor", it tracks *"inside the top-level
`include:` value"* and, within it, each list entry's `project:` / `ref:` / `component:` /
`template:` / `remote:` / `local:` keys. Three consequences:

- `project:` and `ref:` are **two sibling scalars in one mapping**, so the dependency is built
  after the entry's `MappingEnd`, not at a single scalar event. The receiver buffers
  `(project_value, project_marker, ref_value, ref_marker, style)` per entry. `name_range`
  spans the `project:` value; `version_range` spans the `ref:` value.
- `include:` accepts a bare string, a list of strings, a single mapping, or a list of
  mappings. A bare-string entry is a `local:` shorthand → skipped (FR-003).
- **Multi-document input must reset per-document state.** GHA's receiver ignores
  `Event::DocumentStart`/`DocumentEnd` (`parser.rs:353-356`) because a workflow file is never
  multi-document. A GitLab CI **component** file uses the `spec:` header form
  (`spec: … \n--- \n job:`), so a receiver that carried document 1's nesting depth into
  document 2 would mis-scope "top-level `include:`" — either missing a real include or
  admitting a nested one. Handle `DocumentStart` by resetting depth, the in-`include:` flag
  and any half-built entry buffer; handle `DocumentEnd` by discarding an unterminated entry.
  Cover both directions with a fixture.

FR-016 falls out for free: `image:`/`services:` are never under `include:`, so the receiver
never sees them.

Malformed entries: `warn_rejected_value("classify_include", …)` — logs the value's *length*,
never the raw text (`deps-core/src/lsp_helpers/mod.rs:1117`, security S-5 precedent) — and
skip (FR-015).

The host cap of §4.6 is enforced here, at the point a `component:` prefix is first turned into
a `GitlabHost`.

## 7. Version index

GHA's `TagIndex { tag_to_sha, sha_to_tag }` carries over unchanged in shape, keyed by
`PackageName` (now host-qualified per §3.1, which is what makes it instance-correct), with the
same `MAX_TAG_INDEX_ENTRIES` eviction and the same "prefer a full-semver-parseable tag name
when several tags share a SHA" rule (#503 critic S1). It is what lets a SHA pin render a
readable `**Resolved**` hover line. It is populated from whichever endpoint the route used —
tag names for `project:`, release tag names for `component:`.

**Not** carried over: GHA's mutable-ref-pin diagnostic and "Pin to commit SHA" quickfix
(#473). Those are a GitHub-supply-chain-hardening feature outside this spec's FR set; adding
them here would be scope creep and would need its own spec (§10).

## 7a. The `Registry` impl surface — every method, including the source-unaware ones

> [!important] Revision 3 — new section
> §3 moved the host out of `PackageName`, which means a `&PackageName` alone is **not
> routable**. Revision 2 specified only `get_versions_from`, leaving the source-unaware half
> of the trait — which has live callers — undefined. Both readings a reader could pick were
> wrong: a silent empty list kills version completions for every GitLab CI include, and a
> `gitlab.com` default re-creates the wrong-host fetch *and* attaches the token, since
> `gitlab.com` is the default token host (§4.5). `deps-go` avoids the question only because
> it has a real default (`proxy.golang.org`); GitLab CI has none.

| Method | Behavior |
|---|---|
| `get_versions` (required, no default) | `Err(DepsError::PackageNotFound { package: name, registry: "gitlab-ci (no route; source required)" })`, **unconditionally**. Never guesses a host |
| `get_versions_with` | default (forwards to `get_versions`) — not overridden |
| `get_versions_from` | dispatches on `AlternateRegistry { index }` → route table → `(origin, endpoint)` fetch. Unregistered index → `PackageNotFound`. Every other source → delegates to `get_versions_with`, i.e. lands on the same `PackageNotFound` |
| `get_latest_matching` | same unconditional `PackageNotFound` (it is `get_versions`' counterpart and equally unroutable) |
| `get_latest_matching_from` | **overridden**, same dispatch and same "never fall back to a source-unaware default" invariant as `get_versions_from`. This is the second half `deps-go` overrides (`registry.rs:773` **and** `:811`) and revision 2 omitted; hover's `list_fallback_latest` and the background fetch's fallback are its two real call sites |

Returning `PackageNotFound` rather than an empty `Ok(vec![])` is deliberate: an empty list
reads as "this project has no tags", which the caller would render as a resolvable-but-empty
package, whereas `PackageNotFound` is the honest "this call site cannot route" and is the
same error `deps-go` returns for an unregistered index.

### 7a.1 Keeping version completions working

`PackageNotFound` from `get_versions_with` would otherwise silently kill version completions:
`complete_versions_generic` — the helper §8.1 uses, copying GHA
(`deps-github-actions/src/ecosystem.rs:143`) — calls `registry.get_versions_with(name,
freshness)` with **no source** (`deps-core/src/completion.rs:875`) and returns `vec![]` on any
error. Every other ecosystem completes versions; silently not doing so would be an undeclared
NFR-004/FR-013 divergence.

Add a source-aware sibling in `deps-core`, and make the existing helper delegate to it:

```
pub async fn complete_versions_generic_from(
    registry: &dyn Registry,
    package_name: &PackageName,
    source: &DependencySource,
    prefix: &str,
    operator_chars: &[char],
    freshness: FreshnessSettings,
) -> Vec<CompletionItem>          // identical body, but calls get_versions_from

pub async fn complete_versions_generic(...) -> Vec<CompletionItem> {
    complete_versions_generic_from(registry, name, &DependencySource::Registry, ...).await
}
```

Extraction, not a fork — same discipline as §4.4 and §6.1. That body carries the
`is_safe_version_string` manifest-write-sink hardening on `insert_text`/`text_edit`
(`completion.rs:900+`); copying it into this crate would fork a security check. The delegation
is behavior-preserving for all 18 existing call sites across 13 ecosystem crates, since the
default `get_versions_from` drops `source` and forwards to `get_versions_with`.

`GitlabCiEcosystem::generate_completions` then resolves the source before calling it: on
`CompletionContext::Version { package_name, prefix }`, find the dependency in
`parse_result.dependencies()` (`deps-core/src/ecosystem.rs:166`) whose `name()` equals
`package_name`, take its `source()` (`ecosystem.rs:217` — returns an owned
`DependencySource`), and pass it through. No match ⇒ empty completions (an internal
inconsistency, not a user-visible state).

> [!note] Two consequences worth stating rather than discovering later
> - **An unresolved-host include gets no version completions.** Its source is
>   `CustomRegistry`, which routes nowhere. This is consistent with FR-012 — it has no hover
>   version data and no outdated diagnostic either — rather than a new divergence, but it is
>   now an Edge Case row in spec.md so it ships as declared scope.
> - **The other routing ecosystems are not migrated in this PR.** `deps-go`, `deps-pypi`,
>   `deps-nuget` and `deps-cargo` all route on source yet still call the source-unaware
>   helper, so an alternate-registry dependency's version completions fall back to the public
>   registry's list today. That is a pre-existing bug this section merely makes visible; file
>   it as a follow-up (`bug`, P2) rather than widening this PR.

## 8. Ecosystem + LSP wiring

### 8.1 `GitlabCiEcosystem`

```
id() -> "gitlab-ci"
display_name() -> "GitLab CI/CD"
manifest_filenames() -> &[".gitlab-ci.yml"]
manifest_directory_patterns() -> &[(".gitlab/ci", ".yml"), (".gitlab/ci", ".yaml")]
lockfile_filenames() -> &[]
```

Only `.gitlab-ci.yml` — GitLab does not accept `.gitlab-ci.yaml`. The directory pattern covers
the standard split-pipeline convention. Per spec FR-001 as revised, that is the **whole** of
v1's detection: a child pipeline at `ci/build.yml` or `templates/*.yml` is not detected,
because no filename convention distinguishes it from any other YAML file, and reading one out
of a parent's `include: - local:` list is nested-include resolution, which the spec excludes.
US-003's acceptance criteria now scope to FR-001-detected files, so the story is deliverable as
written rather than silently narrower than it promises.

> [!warning] Do not use `manifest_patterns` (e.g. `*.gitlab-ci.yml`)
> `EcosystemRegistry::register` carries a `debug_assert!` requiring the entire registered
> pattern set to belong to **one** ecosystem (`ecosystem_registry.rs:136-143`), and
> `deps-pypi` already owns it (`requirements*.txt` et al.). Registering a GitLab pattern
> panics every debug build and the whole test suite. `manifest_directory_patterns` has no such
> constraint (GHA already registers two).

`parse_manifest` additionally registers the parse's routes into the shared registry (§4.6),
mirroring `deps-go/src/ecosystem.rs:205-215`, then runs the §3.2 downgrade pass over whatever
routes registration refused, before returning the parse result.

`generate_completions` → version completions only (`CompletionContext::Version`), same as GHA;
`PackageName` completion returns empty (no cheap GitLab search endpoint under NFR-002's
budget). Unlike GHA it calls the **source-aware** `complete_versions_generic_from` (§7a.1),
having first resolved the dependency's `source` from `parse_result` — the source-unaware
helper cannot route here and would return nothing.

Overrides beyond the shared defaults, minimal by design (NFR-004):

- `generate_diagnostics` — append the FR-012 informational unresolved-host diagnostic
  (`severity: INFORMATION`, own stable diagnostic code `unresolved-gitlab-host`) to
  `generate_diagnostics_from_cache`'s output, for every dependency whose `HostRef` is
  `Unresolved`. Its message names the `registries.gitlab_instance_host` setting as the remedy
  — that is the whole reason the setting exists, and a diagnostic that says "cannot determine
  the host" without saying how to fix it is the kind of dead end `deps-core`'s own wording
  rules avoid. Truncate interpolated values through
  `deps_core::lsp_helpers::truncate_for_diagnostic`, per GHA's
  `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS` precedent. Note that the source is
  `CustomRegistry` for exactly this set (§3.2), so the shared rules emit nothing competing.
- `generate_hover` — splice via GHA's `splice_resolved_line` shape
  (`deps-github-actions/src/ecosystem.rs:380`): a `**Resolved**` line for a SHA pin, plus —
  **for `component:` includes only** — a `**Project**` link line, since those are the one
  kind whose heading link is suppressed (§8.2). A `project:` include keeps the standard
  heading link and gets no spliced project line, so it renders exactly like every other
  ecosystem.

Everything else (inlay hints, code actions, code lens) uses the `deps_core::lsp_helpers`
defaults unchanged. FR-009/FR-010 are satisfied by those defaults, not by new code.

### 8.2 Formatter

Six sub-traits, following `GithubActionsFormatter`:

- `PackageNaming::validate_package_name` → `is_valid_gitlab_coordinate` (§4.3). Note that this
  predicate runs on *every* dependency regardless of source — it is R5's first arm and fires
  ahead of the `can_resolve_source` gate (`diagnostics.rs:978-987`) — which is exactly why
  §4.3 defines it as a shape-agnostic syntactic gate that accepts both the host-qualified and
  bare forms.
- `SourcePolicy::can_resolve_source` → `matches!(source, Registry | AlternateRegistry { .. })`,
  the standard routing-ecosystem override. Pure function of `source`; see §4.5 for why it must
  not read live configuration.
- `SourcePolicy::source_is_public_registry_content` → default (`false` for
  `AlternateRegistry`), suppressing OSV and deps.dev by design (§3.2).
- `PackageRendering::suppress_package_url` → **`true` for `component:` includes only**, with
  `package_url` returning `""` for those as defense-in-depth (#474).

  > [!important] Revision 3 — the divergence is narrowed to the one kind that needs it
  > Revision 2 suppressed the heading link for *every* GitLab CI include, on the grounds that
  > `package_url` sees only the name. That is broader than necessary: the predicate's
  > signature is `suppress_package_url(&self, source: &DependencySource)`
  > (`deps-core/src/lsp_helpers/formatter.rs:149`), and after §3's routing change the route
  > key hashes the **endpoint**, so a `Tags` route and a `Releases` route produce different
  > `AlternateRegistry.index` values. The formatter can therefore distinguish the two kinds —
  > it holds the route-table handle exactly as `GithubActionsFormatter` holds its
  > `Arc<DashMap<PackageName, Arc<TagIndex>>>` (`deps-github-actions/src/formatter.rs:19-25`).

  Resolution rule, fail-closed:

  | Source | `suppress_package_url` | Why |
  |---|---|---|
  | `AlternateRegistry` → `EndpointKind::Tags` (`project:`) | `false` | `name` is exactly `{host}/{project_path}`, so `https://{name}` is the correct project URL and the standard `# [name](url)` heading (`hover.rs:409-421`) renders as in every other ecosystem |
  | `AlternateRegistry` → `EndpointKind::Releases` (`component:`) | `true` | the name's final segment is the component, not part of the project path — `https://{name}` would be a dead link |
  | `CustomRegistry` (unresolved host, FR-012) | `true` | the name carries no host at all |
  | index not in the route table | `true` | unreachable after §3.2's downgrade pass; suppress rather than guess |

  Because `package_url` is *not called* when the predicate is `true` (`hover.rs:140-141`), the
  `component:` name never reaches URL construction. For that kind only, the project link is
  spliced into the hover body by §8.1's `generate_hover` override, which has the typed
  dependency and renders `https://{host}/{project_path}` correctly, gated on the same
  `is_valid_gitlab_coordinate` predicate. That is the whole of the NFR-004 divergence: for
  `component:` includes the project link sits one hover section lower. It is recorded in
  spec.md (Edge Cases + NFR-004), not only here.
- `RequirementResolution::is_requirement_up_to_date` / `requirement_is_unresolved` — the
  partial-semver leading-component comparison; a SHA or branch ref is
  `requirement_is_unresolved`.
- `format_version_replacing_for` → preserve the pin's `v`-prefix style
  (`deps_core::lsp_helpers::match_v_prefix_style` after §6.1's extraction) and, for a
  `Partial`/`Latest` pin, **return `current` unchanged** — bumping `1.2` to `1.3.0` changes the
  pin's *kind*, not just its value, and the shared no-op guard then correctly suppresses the
  code action.
- `DiagnosticMessages`, `DiagnosticPolicy`, `OsvNaming` — defaults (`OsvNaming::osv_version`
  strips `v`, as GHA does; it is unreachable in practice given the bullet above).

### 8.3 Manifest / workspace changes

1. Root `Cargo.toml` `[workspace.dependencies]`:
   `deps-gitlab-ci = { version = "0.12.1", path = "crates/deps-gitlab-ci" }` — alphabetical,
   directly after `deps-github-actions`. `members = ["crates/*"]` picks the crate up with no
   further edit.
2. `crates/deps-lsp/Cargo.toml`: `gitlab-ci = ["dep:deps-gitlab-ci"]`, appended to `default`,
   plus `deps-gitlab-ci = { workspace = true, optional = true }`.
3. `crates/deps-lsp/src/lib.rs`: add
   `gitlab_instance_host: Arc<std::sync::RwLock<Option<String>>>` to `EcosystemRuntime`
   alongside `nuget_user_profile_sources` — that struct exists (issue #561 M3) precisely so
   this function's arity does not grow per cross-ecosystem live flag. **The field is a raw
   `String`, not a `deps-gitlab-ci` type** (§4.5's revision-3 note): `EcosystemRuntime` is
   un-`cfg`'d and built with plain struct literals in un-`cfg`'d code
   (`document/state.rs:534-537`, `lib.rs:382-385`), so a type from an `optional = true` crate
   would force `#[cfg]` onto the field and every literal. Both existing literals gain one
   line; no `#[cfg]` anywhere. Registration itself is written out **explicitly**, not via
   `register!` — the ecosystem needs `Arc::clone(&runtime.policy)` and
   `Arc::clone(&runtime.gitlab_instance_host)` threaded through a `with_context` constructor,
   exactly as `pypi`, `go` and `nuget` already are, and it is that constructor which builds
   the crate-local `GitlabInstanceHost` (raw handle + policy + memo) from the two.
4. `crates/deps-lsp/src/config.rs`: `registries.gitlab_instance_host: String`
   (`#[serde(default)]`, default `""`) on `RegistriesConfig`, plus the `initialize` /
   `did_change_configuration` call sites that write it into the shared handle (`""` ⇒ `None`).
   **No validation here** — `deps-lsp` must not depend on `deps-gitlab-ci` for host semantics;
   an invalid value is rejected on read (§4.5). Document the security role (§4.5) on the
   field, not only the resolution role — it *moves* a credential's destination, which is the
   more consequential half — and document the already-open-document limitation (§4.5) so the
   setting's own docs do not overclaim.
5. `crates/deps-gitlab-ci/Cargo.toml` deps: `dashmap`, `deps-core`, `semver`, `serde`,
   `serde_json`, `tokio` (`macros`,`sync`), `tower-lsp-server`, `tracing`, `url`,
   `urlencoding`, `yaml-rust2`, `zeroize`. Dev-deps: `deps-core` (`test-util`), `mockito`,
   `tokio` (`macros`,`rt-multi-thread`), `tokio-test`. `[lints] workspace = true`.
6. Docs: `crates/deps-gitlab-ci/README.md`, root `README.md` ecosystem table + tests badge,
   `docs/ECOSYSTEM_GUIDE.md`, `CHANGELOG.md` `[Unreleased]` (one line + PR link).
7. `crates/deps-zed` is a git submodule — **do not touch** (`.claude/rules/branching.md`).

## 9. Resolved decisions

Two gaps this plan found in the spec's FR set were put to the issue owner and resolved
2026-09-04; both are recorded in `spec.md` as **FR-011a** / **FR-005a** with matching Edge
Cases rows. §4.5 is the implementation detail for both.

### 9.1 `include: - project:` has no host segment — ever (resolved: opt-in configured host)

FR-011 as originally written assumes a `project:` include may carry "a literal, hardcoded
GitLab hostname". It cannot. GitLab's syntax is `project: <group>/<project>` + `ref:` +
`file:`; the instance is always implicit (`$CI_SERVER_FQDN`). Under Decision 1 alone, **every**
`project:` include would fall into FR-012's informational skip — making US-001 undeliverable
and SC-002 vacuous, since only `component:` includes carry an explicit `<fqdn>/…` prefix.

**Resolved**: opt-in `registries.gitlab_instance_host`, default unset. When unset, behavior is
byte-identical to Decision 1. When set, `project:` includes and `$CI_SERVER_FQDN`-relative
`component:` includes resolve against it.

This does not contradict Decision 1, which rejected *guessing* — a hardcoded default host, or
inferring one from a git remote. An explicit user declaration is not a guess, and it is the
same mechanism Renovate exposes (`endpoint`). Rejected alternatives: accepting US-001 as a
permanent no-op, and narrowing v1 to `component:` includes only.

### 9.2 `GITLAB_TOKEN` must not be sent to an arbitrary host from file content

A `component:` include's host is attacker-influenced content: opening any repository whose
`.gitlab-ci.yml` contains `include: - component: attacker.example/a/b/c@1.0` would send the
developer's `GITLAB_TOKEN` to `attacker.example` as a `PRIVATE-TOKEN` header.
`validate_index_url` does not prevent this — such a host is perfectly valid and public.

**Resolved**: the token goes to exactly one host — `gitlab.com` by default, **replaced** by
`registries.gitlab_instance_host` when set (§4.5; revised from revision 1's union, which would
have leaked a self-hosted PAT to `gitlab.com`). Every other host is still fetched, subject to
`validate_index_url`'s `HostClass` gate, but unauthenticated. The comparison runs on the
normalized, ASCII-serialized origin. This is a security-relevant default and carries a
dedicated regression test (§11).

### 9.3 Smaller items — resolved during design, no user input needed

- **FR-014 vs. GitLab's status codes.** GitLab returns `401` for a missing/invalid token,
  `403` for insufficient scope, `404` for a private project the token cannot see (it does not
  leak existence), and `429` for rate limiting — not GitHub's `403`-means-rate-limit. The
  `map_tags_error` mapping must therefore differ from `deps-github-actions`'
  (`registry.rs:216`): `429` → a `RateLimited` message shaped like
  `deps_core::github::github_rate_limit_error` (`github.rs:129`) naming `GITLAB_TOKEN`,
  plus the cooldown gate; `401`/`403` → an auth message; `404` → `PackageNotFound`. Copying
  GHA's arms verbatim would mislabel every case.
- **Rate-limit cooldown gate scope.** GHA's `RateLimitGate` is process-wide, correct for a
  single fixed host. GitLab's must be **per host** (a `DashMap<origin, AtomicU64>` bounded by
  the same §4.6 route cap) — one self-hosted instance rate-limiting must not disable lookups
  against `gitlab.com`.
- **Release dates / freshness.** `component:` gets `published_at` for free from `/releases`
  (§3, §5). `project:` tags carry no publish date — only a commit date, which would misreport
  freshness — so `published_at` stays `None` there and `get_versions_with` is not overridden
  beyond delegating to `get_versions`. File a follow-up only if tag-date freshness is wanted.
- **Component-name path split.** `<fqdn>/<project-path>/<component-name>@<version>` with
  arbitrary-depth subgroups is only splittable by the rule "last segment is the component
  name" (GitLab's own documented shape). That rule is correct but has no server-side
  confirmation available offline; note it in the parser's doc comment.

## 10. Explicitly out of scope for this crate

`image:`/`services:` Docker tags (FR-016), nested `include:` recursion (and therefore
conventionless child-pipeline paths, §8.1), catalog metadata (GraphQL-only), custom CA / mTLS
(Decision 5), GitHub-style mutable-ref-pin diagnostics and SHA-pin quickfixes (#473 is
GHA-specific and unspec'd here), workspace-wide aggregation, the server-wide
re-parse-on-config-change facility (§4.5 — a separate follow-up issue), and migrating the
other routing ecosystems to source-aware version completions (§7a.1 — a pre-existing bug this
plan surfaces but does not fix).

## 11. Test plan

Per `.claude/rules/testing.md` — `cargo nextest`, inline `#[cfg(test)] mod tests`, `mockito`
for HTTP, `#[tokio::test]` for async.

- **`parser.rs`** — every `include:` form (bare string, string list, single mapping, mapping
  list); `template:`/`remote:`/`local:` skipped silently; quoted vs. plain scalars; duplicate
  includes get distinct ranges; `image:`/`services:` in the same file produce nothing;
  **multi-document `spec:` + `---` fixtures in both directions** (an `include:` in document 2
  is found; a nested key in document 2 is not mistaken for a top-level `include:`);
  adversarial fixtures (deep nesting, expansion bomb, YAML aliases, non-ASCII text before a
  `component:` value to exercise `CharOffsets`, multi-byte leading whitespace in a quoted
  scalar).
- **Host fan-out cap (§4.6)** — a document naming 12 distinct `component:` hosts registers at
  most 8 routes, and the 9th-plus dependencies are `HostRef::Unresolved` with no transport
  touched (assert on mockito hit counts, not on an internal counter). Separately, a
  process-wide overflow test mirroring `deps-go`'s
  `test_register_chain_at_capacity`-shaped case — and, on top of it, the §3.2/§4.6 downgrade
  assertion: a dependency whose route the process-wide cap refused ends up with
  `CustomRegistry` and the FR-012 informational diagnostic, and **no** "Registry lookup
  failed" diagnostic.
- **`component.rs`** — pure unit tests over the full FR-007 priority ladder against a
  *release* list: `abc…` SHA, exact release, `~latest`, `1.2`, `1`, `v1.2` against
  `v`-prefixed release names (the normalization case revision 1 got wrong), an unmatched
  partial, a branch-shaped ref. Plus the S2 regression: **a tag that exists but has no
  release is never selected** — assert against a fixture where `/repository/tags` contains
  `2.0.0` and `/releases` stops at `1.9.0`, and `~latest` resolves to `1.9.0`.
- **`client.rs`** (mockito) — pagination across pages for both endpoints; cross-origin
  redirect blocked (assert the status code only, never format the error — CodeQL
  cleartext-logging, per `github.rs`'s own test comment); `401`/`403`/`404`/`429` each mapped
  to its own error; project path percent-encoded in the request path; the `order_by=version`
  → `400` → retry-without-`order_by` degradation.
- **Token-host containment (§9.2 regression, security-relevant — do not skip).** With a token
  set: header **present** for `gitlab.com` with the setting unset; header **absent** for
  `attacker.example`; header **present** for `gitlab.mycorp.dev` once that host is the
  configured `gitlab_instance_host`; header **absent for `gitlab.com`** under that same
  setting (the revision-2 replace-not-union case — a union would have leaked the corporate PAT
  here); header still absent for `gitlab.mycorp.dev.attacker.example` (the suffix-lookalike
  case the normalized-origin comparison exists for). Assert on `mockito`'s `match_header` /
  `Matcher::Missing`, i.e. on the wire, not on an internal predicate's return value.
- **`GitlabInstanceHost::get`** — a configured `http://` / userinfo-bearing / `127.0.0.1` /
  `169.254.169.254` value reads back as `None` (validation runs on read, §4.5) and the token
  host stays `gitlab.com`; a valid value reads back as the parsed `GitlabHost`; changing the
  raw string invalidates the memo, so the new value is re-validated rather than served from
  the previous outcome.
- **`Registry` surface (§7a)** — `get_versions` and `get_latest_matching` return
  `PackageNotFound` for a name that *does* have a registered route (proving they never guess a
  host, not merely that an unknown name fails); `get_versions_from` and
  `get_latest_matching_from` both resolve that same name+source pair successfully; both `_from`
  methods return `PackageNotFound` for an `AlternateRegistry` index that was never registered.
- **Version completions (§7a.1)** — `deps-core`: `complete_versions_generic` produces
  byte-identical items before and after the delegation (assert against a stub registry that
  ignores `source`). This crate: a version completion on a resolvable `component:` pin returns
  the release list; on an unresolved-host include it returns empty (the declared Edge Case).
- **`GitlabHost::parse`** — rejects `http://`, userinfo, `127.0.0.1`, `169.254.169.254`,
  `::ffff:169.254.169.254`, and the §4.1 round-trip cases (`gitlab.com?x`, `gitlab.com/x`,
  `gitlab.com:8080@evil.test`).
- **Routing (§3.2)** — a `project:` include with the setting unset yields `CustomRegistry`,
  the FR-012 informational diagnostic, **no** "Unknown package" diagnostic, and zero registry
  calls; with the setting set it yields `AlternateRegistry` and resolves. Same for a
  `$CI_SERVER_FQDN`-relative `component:` include. Plus a name-collision test: a `project:`
  and a `component:` include of the same project on the same host produce **distinct**
  `PackageName`s and do not overwrite each other's cached versions.
- **`config.rs`** — `registries.gitlab_instance_host` deserializes, defaults to `""`, and a
  payload omitting it still parses (additive-safety, mirroring
  `test_registries_config_section_deserialization`).
- **`deps-core` extractions (§4.4, §6.1, §7a.1)** — `deps-github-actions` and `deps-swift` test
  suites must pass unchanged, and `warn_if_pagination_truncated`'s GitHub log text must be
  byte-identical after gaining the `provider` and `max_pages` parameters. Plus a direct test
  that the warning **fires on the last page for a non-30 `max_pages`** — the regression M8
  guards: with `max_pages = 3`, `page == 3` and a full page must warn, and `page == 30` must
  not.
- **Registry gate.** `.claude/rules/continuous-improvement.md` requires a live check against
  the real registry before the PR: hover a real `gitlab.com` catalog component (e.g.
  `gitlab.com/components/opentofu/…@1.0`) and confirm the resolved version is current **and
  that it came from `/releases`** (check the debug log's request URL), plus a real
  `project:`+`ref:` include against a public gitlab.com project with the instance host
  configured.
- **Hover heading link (§8.2, M7).** A resolvable `project:` include renders the **standard**
  `# [name](url)` heading link (no divergence) and splices no `**Project**` body line; a
  `component:` include renders no heading link and does splice one. Assert on the rendered
  markdown, not on `suppress_package_url`'s return value.
- **Cross-ecosystem consistency (NFR-004/FR-013).** Compare hover markdown, diagnostic wording
  and inlay-hint format side-by-side against `deps-github-actions` for the equivalent
  scenario; record the one intentional divergence (§8.2's `component:`-only project link in
  the body rather than the heading) in `.local/testing/coverage.md`'s LSP Feature Matrix and
  add a `playbooks/gitlab-ci.md`.

## 12. Suggested implementation order

1. **`deps-core` extractions** — `deps_core::pagination::paginate_pages` (§4.4), the
   `lsp_helpers` span/text helpers (§6.1), and `complete_versions_generic_from` (§7a.1).
   Mechanical, own commit, `deps-github-actions` and `deps-swift` stay green. All three are
   prerequisites, not cleanup.
2. Crate skeleton + `types.rs` + `Cargo.toml`/workspace wiring; ecosystem registered but
   parsing nothing.
3. `host.rs` — `GitlabHost` (+ round-trip validation), `GitlabInstanceHost` (validate-on-read
   + memo), the token-host rule, `is_valid_gitlab_coordinate`, the
   `registries.gitlab_instance_host` config field and its raw-`String` `EcosystemRuntime`
   threading (§4.5, §8.3 items 3/4), with the host-validation and config tests.
   **Deliberately ahead of the client**: the token host is a security-relevant default, so
   its gate and its tests exist before any code that attaches a credential.
4. `parser.rs` + its tests, including multi-document and the §4.6 per-document host cap
   (largest single unit; no network).
5. `registry.rs` route table + `register_chain`-shaped registration + the §4.6 process-wide cap
   + the §3.2 downgrade pass + the full §7a `Registry` surface (`get_versions` /
   `get_latest_matching` as unconditional `PackageNotFound`, `get_versions_from` **and**
   `get_latest_matching_from` dispatching) — before the client, so routing is testable
   against a stub.
6. `client.rs` + mockito tests, including the §9.2 token-host regression set and both
   endpoints.
7. `component.rs` + pure tests (releases-based).
8. Version index + per-host rate-limit gate.
9. `formatter.rs` + `ecosystem.rs` overrides (FR-012 diagnostic, hover splices).
10. Docs, CHANGELOG, README, ECOSYSTEM_GUIDE, live registry gate. File the two follow-up
    issues: server-wide re-parse-on-config-change (§4.5, `enhancement`, P3) and
    source-unaware version completions in the other routing ecosystems (§7a.1, `bug`, P2).

Nothing is gated on an open question. Revision 3's changes, like revision 2's, are design
decisions with citations, not new clarification requests.

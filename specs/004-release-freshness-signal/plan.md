---
aliases:
  - Release Freshness Signal Plan
tags:
  - sdd
  - plan
  - deps-core
created: 2026-08-23
status: approved
spec: "[[004-release-freshness-signal/spec]]"
---

# Implementation Plan: Release-Freshness Signal (issue #145)

> **Sign-off status (2026-08-23):** all six open items (G1–G6) resolved by the
> user via team-lead. v1 scope is **6 ecosystems**; `did_change_configuration`
> is **in scope** for this PR. See §7 for the decision record.

## 0. Scope correction — spec assumptions verified live (2026-08-23)

The spec's Current State table and NFR-001 are **factually wrong for 6 of 11
ecosystems**. Verified by reading the crates' serde structs *and* by live
`curl` against every registry.

| Ecosystem | Timestamp in the payload the crate *already fetches*? | Verified how | v1 |
|---|---|---|---|
| deps-cargo | **YES** — sparse index NDJSON now carries `pubtime`, 100% coverage (195/195 for `tokio`, incl. 2016 releases). Format `2026-07-18T23:05:13Z` | `curl index.crates.io/se/rd/serde`, `/to/ki/tokio` | ✅ |
| deps-pypi | **YES** — PEP 700 `files[].upload-time` in the already-requested PEP 691 JSON (api-version 1.4). Format `2026-05-14T19:25:27.735762Z`. Per **file**, not per version | `curl -H 'Accept: application/vnd.pypi.simple.v1+json' pypi.org/simple/requests/` | ✅ |
| deps-composer | **YES** — p2 payload has `time` on every entry. Format `2026-01-02T08:56:05+00:00` (numeric offset). Also a `published-time` sibling | `curl repo.packagist.org/p2/monolog/monolog.json` (87/87 entries) | ✅ |
| deps-bundler | **YES** — `created_at` already parsed into `BundlerVersion` and discarded | code | ✅ |
| deps-dart | **YES** — `published` already parsed into `DartVersion` and discarded | code | ✅ |
| deps-go | **PARTIAL** — `/@latest` returns `Time` and `parse_version_info` already stores it; `/@v/list` (used by `get_versions`) is plain text with no dates | `curl proxy.golang.org/.../@latest` | ⚠️ partial |
| deps-npm | **NO** — the abbreviated packument (`application/vnd.npm.install-v1+json`) omits the top-level `time` object. Top keys are exactly `dist-tags, modified, name, versions`. Full packument is **2.37×** larger (804 975 vs 339 376 B for `express`) | `curl` both variants | ❌ defer |
| deps-maven / deps-gradle | **NO** — `maven-metadata.xml` has no per-version dates (only `<lastUpdated>` per artifact). `MavenVersion.timestamp: Option<u64>` is **dead code**: both construction sites pass `None` | `curl repo1.maven.org/.../guava/maven-metadata.xml` | ❌ defer |
| deps-nuget | **NO** — flat container `index.json` is a bare `{"versions": [...]}`. `published` lives in the registration hive, which `ServiceIndex::resolve` does not fetch (deliberately deferred, `registry.rs:4-6`) and which is paged | `curl api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json` | ❌ defer |
| deps-swift | **NO** — version data comes from the GitHub **tags** API, which has no date field at all. Needs N commit lookups or a switch to the releases API (misses tag-only packages). Crate is already rate-limit sensitive | code + GitHub API shape | ❌ defer |

**Consequences (all confirmed by the user 2026-08-23 — see §7):**
- v1 covers **6 ecosystems** (5 full + Go partial), not 10–11. npm, Maven/Gradle,
  NuGet and Swift are **out of this PR**; team-lead files one follow-up issue per
  ecosystem after it lands.
- **FR-008 is unsatisfiable for Maven** (the field it says to "wire" is never set) and only partially for Go.
- **FR-007 is satisfiable for Cargo, PyPI and Composer at zero network cost** — better than the spec assumed. It is *not* satisfiable for npm/NuGet/Swift without a real cost.
- **SC-001's "100% of ecosystems" target must be restated** as "100% of ecosystems where the timestamp is available without an added network round trip".
- NFR-001 (no added round trips) is therefore what *defines* v1 scope, and it holds unconditionally.

### Two data channels (critical, not mentioned in the spec)

| Channel | Source | Feeds | Shape |
|---|---|---|---|
| **Ch1** | `Registry::get_latest_matching` → `fetch_latest_versions_parallel` (`deps-lsp/src/document/lifecycle.rs:137-205`) | diagnostics, inlay hints, hover's `**Latest**:` line | **lossy** — `Box<dyn Version>` collapsed to `String` at `lifecycle.rs:161-167`, stored in `DocumentState::cached_versions: HashMap<String,String>` (`state.rs:45`) |
| **Ch2** | `Registry::get_versions` called live per request (`lsp_helpers.rs:536`, `completion.rs:680`, `lsp_helpers.rs:646`) | hover's "Recent versions" list, completion, code actions | full `Vec<Box<dyn Version>>` |

Ch2 needs only the new trait method. **Ch1 needs a widening of `DocumentState`
and `VersionData`** — this is the single largest structural cost of the feature
and the spec does not mention it. Go is Ch1-only.

---

## 1. Core design — `deps-core`

### 1.1 New dependency

Add to `[workspace.dependencies]` and to **`crates/deps-core/Cargo.toml` only**:

```toml
time = { version = "0.3", default-features = false, features = ["std", "parsing"] }
```

- Latest observed is **0.3.55**, published 2026-08-01 → actively maintained.
  **Developer MUST re-check the current version via context7 mcp before adding
  it** (project dependency policy) — do not copy `0.3.55` on faith.
- Required deps are `deranged`, `num-conv`, `powerfmt`, `time-core` — all tiny/no-std.
- `Rfc3339` parses every format we need: bare `Z`, arbitrary fractional digits,
  and numeric offsets (`+00:00`) — covers Cargo, PyPI, Composer, Bundler, Dart, Go.
- Rejected `chrono` (heavier, tz machinery we do not need, historic `localtime_r`
  advisory) and `jiff` (excellent but ships a tzdb — overkill for "parse RFC3339").
- **We do not use `time` for "now"** — `std::time::SystemTime` is used instead, so
  no `wasm-bindgen`/`local-offset` feature is ever needed.
- ACTION: developer must re-verify the version via context7 mcp per the user's
  dependency policy before adding it.

### 1.2 New module `crates/deps-core/src/freshness.rs`

Deliberately minimal — three items, no policy struct, no builder.

```rust
/// Dependabot's default cooldown (3 days) in seconds.
pub const DEFAULT_COOLDOWN_SECS: u64 = 3 * 24 * 60 * 60;

/// A release publish instant, normalized to Unix epoch seconds (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublishTime(i64);

impl PublishTime {
    pub fn now() -> Self;                                   // SystemTime, saturating
    pub const fn from_unix_secs(secs: i64) -> Self;
    pub fn from_unix_millis(ms: i64) -> Self;               // for future Maven/solrsearch
    pub fn parse_rfc3339(s: &str) -> Option<Self>;          // None on any parse failure
    pub const fn as_unix_secs(self) -> i64;
    /// Age in seconds; a future timestamp (clock skew) saturates to 0.
    pub const fn age_secs_from(self, now: Self) -> u64;
}

/// `age < cooldown` — exclusive upper bound, the single documented rule.
pub const fn is_within_cooldown(age_secs: u64, cooldown_secs: u64) -> bool;

/// "just now" | "5 minutes ago" | "2 hours ago" | "3 days ago" |
/// "2 weeks ago" | "5 months ago" | "2 years ago"
pub fn format_relative_age(age_secs: u64) -> String;
```

Rules, applied uniformly (resolves three spec Open Questions):
- **Clock skew**: `published > now` → age clamps to `0` → renders "just now" and
  **counts as within cooldown**. Chosen over suppression because a
  slightly-ahead registry clock is exactly the just-published case the feature
  exists for; suppressing would silently lose the signal when it matters most.
- **Boundary**: `age_secs < cooldown_secs` is fresh; `age == cooldown` is not.
- **Parse failure**: `None`, logged at `trace`, never an error (FR-005).
- `format_relative_age` operates on a `u64` of seconds — plain duration bucketing,
  **not** date arithmetic, so NFR-005 is respected (all date parsing goes through
  `time`).

Export from `crates/deps-core/src/lib.rs` alongside the existing re-exports.

### 1.3 `Version` trait extension — `crates/deps-core/src/registry.rs:135`

```rust
/// When this version was published, if the registry exposes it.
///
/// Default `None` — ecosystems without publish metadata degrade to
/// pre-feature behavior (US-003).
fn published_at(&self) -> Option<PublishTime> { None }
```

Purely additive default method → NFR-003 and SC-004 hold; the 5 not-yet-migrated
ecosystems compile untouched. `PublishTime` is `Copy`, so no lifetime or
borrow complications and `Box<dyn Version>` stays object-safe.

`find_latest_stable` (`registry.rs:202`) is **not** touched — freshness never
influences selection (spec §8 "Never").

### 1.4 `impl_version!` macro — `crates/deps-core/src/macros.rs:110`

The macro is fixed-arity (`version:`, `yanked:`). Add a **second arm** accepting
an optional `published_at: $field:ident`. Two fully-written arms (~12 duplicated
lines) beats a `()`-sentinel trick for readability. Used by deps-npm, deps-pypi,
deps-composer, deps-swift.

---

## 2. Configuration

`crates/deps-lsp/src/config.rs`, following the `CacheConfig` pattern verbatim
(`config.rs:154-183` + validating deserializer `config.rs:283-337`):

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct FreshnessConfig {
    #[serde(default = "default_freshness_enabled")]
    pub enabled: bool,                 // default true
    #[serde(default = "default_cooldown_secs", deserialize_with = "deserialize_cooldown")]
    pub cooldown_secs: u64,            // default 259_200 (3 days)
}
```

- Clamp to `MIN_COOLDOWN_SECS = 0 ..= MAX_COOLDOWN_SECS = 30 days`, `tracing::warn!`
  on clamp (same shape as `deserialize_fetch_timeout`).
- `cooldown_secs: 0` disables the cooldown *callout* but keeps age display;
  `enabled: false` suppresses **all** freshness rendering. Cheap escape hatch.
- Add `#[serde(default)] pub freshness: FreshnessConfig` to `DepsConfig`
  (`config.rs:25-37`).
- Uniform across ecosystems, no per-ecosystem override (FR-010).

**Transport to `deps-core`.** Introduce a `Copy` DTO in `deps-core` (do **not**
overload `EcosystemConfig`, which is inlay-hint-specific):

```rust
#[derive(Debug, Clone, Copy)]
pub struct FreshnessSettings { pub enabled: bool, pub cooldown_secs: u64 }
impl Default for FreshnessSettings { /* true, DEFAULT_COOLDOWN_SECS */ }
```

Threaded as a new parameter to **only two** entry points, chosen to minimize churn:

| Entry point | Change | Override count to fix |
|---|---|---|
| `Ecosystem::generate_hover` (`ecosystem.rs:372-389`) | + `FreshnessSettings` param | **0** — no ecosystem overrides it |
| `Ecosystem::generate_diagnostics` (`ecosystem.rs:418-431`) | + `FreshnessSettings` param | verify with `rg 'fn generate_diagnostics' crates/deps-*/src/` before starting |
| `Ecosystem::generate_completions` | **unchanged** | 13 ecosystems override it — deliberately avoided |

Completion therefore renders **relative age only, no cooldown verdict** — it needs
no config. This is also better UX (no arbitrary cliff mid-list) and still
satisfies FR-004, which lets `/sdd plan` pick the mechanism per surface.

Call sites already hold `Arc<RwLock<DepsConfig>>` and use the
snapshot-before-await idiom: `handlers/hover.rs:22`, `handlers/diagnostics.rs:15`.

**Also fix (2 lines, in scope because we add a config field):**
`server.rs:236` uses `if let Ok(config) = serde_json::from_value::<DepsConfig>(...)`
which **silently discards the entire user config** on any deserialization error.
Add an `Err` arm with `tracing::warn!`. Adding a field widens this bug's blast
radius, so it belongs here.

### 2.1 Live reload — `workspace/didChangeConfiguration` (IN SCOPE, user-requested)

No such handler exists anywhere in the repo today; config is read exactly once at
`initialize`. Build it as part of **T1**, since it is server-wide wiring rather
than ecosystem-specific work.

1. **Shared parse helper.** Extract the `initialize` body at `server.rs:230-252`
   into one function used by *both* entry points, so the `Err`-arm warning above
   exists in a single place:
   ```rust
   fn parse_config(value: serde_json::Value) -> Option<DepsConfig>  // warns on Err
   ```
2. **Handler** on `Backend` (`server.rs`, alongside `did_change_watched_files` at
   `:335`):
   ```rust
   async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
       let Some(config) = parse_config(params.settings) else { return };  // keep previous on error
       *self.config.write().await = config;
       // nudge the client to re-pull, capability permitting
   }
   ```
   Replace-whole-config semantics, matching `initialize`. On a parse error the
   **previous** config is kept — never silently reset to defaults.
3. **Refresh the affected surfaces.** Hover, completion and code actions are
   computed on demand and pick the new value up for free. **Diagnostics are
   pull-based** (`Backend::diagnostic`, `server.rs:424`), so the client must be
   told to re-pull: send `workspace/diagnostic/refresh`, guarded by
   `client_capabilities.workspace.diagnostics.refresh_support` (already stored at
   `server.rs:233`). Inlay hints are unaffected by freshness — do not refresh them.
4. **Client divergence to handle:** some clients send the full settings object in
   `params.settings`, others send `null` and expect the server to pull via
   `workspace/configuration`. v1 handles only the push form; a `null`/absent
   payload is a no-op logged at `debug`. Do **not** implement the pull form or
   dynamic registration in this PR.

Scope guarantee: the acceptance bar is that a changed `freshness.cooldown_secs`
takes effect without restarting the editor. Reloading the rest of `DepsConfig`
comes free from the same code path but is not separately guaranteed — note in
the PR that `CacheConfig` changes still only affect subsequently-fetched
documents.

---

## 3. Ecosystem wiring

Common rule: **parse eagerly at construction** into `published_at: Option<PublishTime>`.
Never store the raw string and parse inside `published_at()` — hover re-renders
would re-parse on every keystroke.

Pre-1.0, so **replace** the existing raw-string fields rather than adding
alongside (user's CLAUDE.md: no back-compat shims before 1.0). Record as a
breaking change in `CHANGELOG.md`.

| Crate | Struct change | Parse site | `impl Version` site |
|---|---|---|---|
| deps-cargo | `CargoVersion` (`types.rs:99`) **+** `published_at: Option<PublishTime>`; `IndexEntry` (`registry.rs:232-241`) **+** `#[serde(default)] pubtime: Option<String>` | `registry.rs:254` | `types.rs:170` (hand-written) |
| deps-pypi | `PypiVersion` (`types.rs:111`) **+** field; `SimpleFile` (`registry.rs:357-361`) **+** `#[serde(rename = "upload-time", default)] upload_time: Option<String>` | near `build_yanked_map` (`registry.rs:466`) — reuse the existing filename→version resolution, take the **minimum** `upload-time` across a version's files | `types.rs:149` (macro, new arm) |
| deps-composer | `ComposerVersion` (`types.rs:78`) **+** field; `MinifiedVersion` (`registry.rs:129`) **+** `time: Option<String>` | `expand_minified_versions` (`registry.rs:142-183`) — **do NOT inherit** `time` through the minified chain; take it only from the entry itself, `None` if absent | `types.rs:84` (macro, new arm) |
| deps-bundler | `BundlerVersion.created_at: Option<String>` (`types.rs:43`) → `published_at: Option<PublishTime>` | `registry.rs:101` | `registry.rs:171` (hand-written) |
| deps-dart | `DartVersion.published: Option<String>` (`types.rs:33`) → `published_at: Option<PublishTime>` | `registry.rs:122` | `registry.rs:152` (hand-written) |
| deps-go | `GoVersion.time: Option<String>` (`types.rs:43`) → `published_at: Option<PublishTime>` | `parse_version_info` (`registry.rs:387/397`) sets it; `parse_version_list` (`registry.rs:350`) keeps `None` | `types.rs:100` (hand-written) |

**deps-maven / deps-gradle / deps-npm / deps-nuget / deps-swift: no change in v1.**
`MavenVersion.timestamp: Option<u64>` stays dead — wiring it would ship a
guaranteed-`None` accessor. Flag it for a separate cleanup issue (it fits the
direction of #198/#200).

Composer note: `time` was present on 87/87 entries live, so the
no-inheritance rule is safe in practice, but it must still be written that way —
inheriting a previous version's publish date would be a correctness bug.

---

## 4. LSP surface rendering

### 4.1 Ch1 widening (required for diagnostics + hover's `**Latest**` line)

Minimal-diff approach — a **parallel map**, matching the existing
`VersionData { cached, resolved }` two-parallel-maps pattern rather than
reshaping `HashMap<String,String>` (which 13 ecosystems' formatters read):

1. `deps-lsp/src/document/lifecycle.rs:137-205` — `fetch_latest_versions_parallel`
   returns a named struct instead of one map:
   ```rust
   pub(crate) struct LatestVersions {
       pub versions: HashMap<String, String>,
       pub published_at: HashMap<String, PublishTime>,
   }
   ```
   Populate `published_at` from `v.published_at()` at `lifecycle.rs:161-167`,
   right where the `Box<dyn Version>` is currently discarded.
2. `deps-lsp/src/document/state.rs` — add
   `latest_published_at: HashMap<String, PublishTime>` (next to `:45`/`:47`)
   plus its setter (next to `update_cached_versions` at `:218`).
3. `deps-core/src/lsp_helpers.rs:35-60` — `VersionData` gains
   `published: Option<&'a HashMap<String, PublishTime>>`.
   `VersionData::new` keeps its **2-argument signature** (sets `None`) and gains
   `with_published(self, map)`. Source-compatible for every existing call site
   and doctest; `Copy` is preserved.

### 4.2 Hover — `lsp_helpers.rs:519-621`

Two insertions, no reordering, no removals.

**(a) The `**Latest**:` line (Ch1)** — append the age when known:
```
**Latest**: `1.2.3` *(published 2 hours ago)*
```
Followed, when the release is within cooldown and `enabled`, by a callout:
```
> ⏳ **Recently published** — this release is still within the cooldown window.
> It may still be yanked or superseded; consider verifying before upgrading.
```
The window duration is deliberately **not** interpolated into the text, so no
awkward duration formatting is needed.

**(b) The "Recent versions" list (Ch2)** — annotate entries whose
`published_at()` is known, preserving the existing `*(latest)*` and
`yanked_label()` markers:
```
- `1.2.3` *(latest)* — 2 hours ago
- `1.2.2` — 3 months ago
- `1.2.1` *(yanked)* — 5 months ago
```
This is what makes US-002's "the previous stable version outside the cooldown
window remains visible as an alternative" true **without touching ordering or
filtering** (FR-006).

Constraints: reuse `escape_markdown` / `markdown_code_span`; the age string is
generated internally so it needs no escaping, but must not be concatenated into
a code span. **No `EcosystemFormatter` hook** for freshness — NFR-002/US-004
require one uniform rendering, unlike `yanked_label()`.

### 4.3 Diagnostics — `lsp_helpers.rs:689-744` (`generate_diagnostics_from_cache`)

- **Severity stays `HINT` in both cases.** Rationale: `HINT` is already the floor,
  so there is nothing "softer"; raising it adds noise; suppressing the diagnostic
  would hide the recommendation, against the spec's intent.
- **Message-only differentiation:**
  - established (or unknown age): `Newer version available: 1.2.3` — unchanged
  - within cooldown: `Newer version available: 1.2.3 (published 2 hours ago — still within the release cooldown window)`
- Do **not** wire `DiagnosticsConfig::{outdated,unknown,yanked}_severity`. Those
  three fields are parsed and then dropped at `handlers/diagnostics.rs:15`
  (`_config`), i.e. dead code. Fixing that is a separate issue — out of scope here.
- Apply the same change to `generate_diagnostics` (`lsp_helpers.rs:753-817`) only
  if trivial; it has no in-workspace callers.

### 4.4 Completion — `completion.rs:474-535`

- `VersionDisplayItem` **+** `pub published_at: Option<PublishTime>`, populated in
  `VersionDisplayItem::new` from the `&dyn Version` it already receives
  (`completion.rs:520`) — this is the one chokepoint where per-version metadata
  is still live.
- `build_version_completion` fills the currently-unused `label_details` slot
  (`CompletionItemLabelDetails` appears nowhere in the repo today):
  ```rust
  label_details: Some(CompletionItemLabelDetails {
      detail: Some(format!("  {}", format_relative_age(age))),
      description: None,
  }),
  ```
  It renders greyed next to the label in VS Code/Zed and, unlike `label`, does
  not participate in filter matching.
- **Unchanged: `label`, `sort_text`, `preselect`, and
  `prepare_version_display_items`' filtering/ordering** — FR-006 is a hard
  invariant here.
- `generate_code_actions` (`lsp_helpers.rs:650`) shares
  `prepare_version_display_items` and simply ignores the new field.

---

## 5. Test plan

**deps-core `freshness.rs`** — the six real-world formats as fixtures:
`2026-07-18T23:05:13Z` (cargo), `2026-05-14T19:25:27.735762Z` (pypi, 6-digit
fraction), `2026-01-02T08:56:05+00:00` (composer, numeric offset),
`2024-01-15T10:30:00.000Z` (bundler), pub.dev fractional form, and Go's bare `Z`
form. Plus: garbage input → `None`; empty string → `None`; future timestamp →
age `0` and within-cooldown `true`; `age == cooldown` → `false`;
`age == cooldown - 1` → `true`; every `format_relative_age` bucket boundary.

**Per ecosystem crate (NFR-004)** — three mockito tests each, following
`deps-bundler`'s existing `test_parse_versions_response_with_created_at`:
present / absent-or-null / malformed. Six crates × 3 = 18 tests.
PyPI additionally: a version whose files have differing `upload-time` values →
the minimum is chosen. Composer additionally: an entry with no `time` must yield
`None`, **not** the previous entry's value.

**LSP surface** — hover markdown assertions (age line present / callout present
within cooldown / both absent when `published_at()` is `None` / both absent when
`enabled: false`); diagnostic message variants; completion `label_details`
present-and-absent plus an assertion that `sort_text`/`preselect`/item count are
byte-identical to the pre-feature output (FR-006 regression guard).

**Config** — defaults, partial JSON, clamping above 30 days, `enabled: false`.

**Live reload (§2.1)** — `parse_config` returns `None` and logs on malformed
input; `did_change_configuration` with a valid payload replaces the stored
config; with a malformed payload **keeps the previous config** rather than
resetting to defaults; with `null` settings is a no-op. Plus an end-to-end
assertion that a diagnostic's message flips between the plain and the
within-cooldown variant when only `cooldown_secs` changes.

**Live verification (NFR-006, blocking)** — `.local/testing/lsp_test.py`, one
package with a release published in the last ~72 h per v1 ecosystem
(cargo/pypi/composer/bundler/dart) plus Go on the Ch1 path only. Record results
in `.local/testing/coverage.md` and a `journal/ci-NNN.md` entry.

**Full gate** — `cargo +nightly fmt --all -- --check`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo nextest run --workspace --all-features --no-fail-fast`, rustdoc gate.
Every new `pub` item needs `///` docs and the non-trivial ones a runnable
`# Examples` doc-test (user's CLAUDE.md).

---

## 6. Task decomposition — recommended split

```
T1  foundation (SERIAL, blocks everything)
    time dep (context7 check first) + deps-core/src/freshness.rs
    + Version::published_at + impl_version! second arm
    + FreshnessConfig/FreshnessSettings
    + parse_config helper & did_change_configuration handler (§2.1)
    + unit tests
    ~250 lines, 6 files

        ├── T2  ecosystem wiring (6 fully independent subtasks, no shared files)
        │       T2a cargo   T2b pypi   T2c composer
        │       T2d bundler T2e dart   T2f go
        │       ~30 lines + 3 tests each
        │
        └── T3  LSP surface (independent of T2 — develop against a mock Version)
                LatestVersions/DocumentState + VersionData.published
                + hover + diagnostics + completion
                ~180 lines, 7 files

T4  integration (SERIAL, after T2 ∥ T3)
    live verification, CHANGELOG, README config table, ECOSYSTEM_GUIDE
```

**T2 and T3 are genuinely parallelizable** — disjoint file sets, and T3 only
depends on the T1 trait method, not on any ecosystem implementing it. With a
single developer the same ordering works serially. T2a–T2f are six independent
one-crate tasks if more parallelism is wanted.

**Superseded 2026-08-23 by critic review + user sign-off — see §7a.** The
"one PR" recommendation below is kept for historical context only; the
"already-parsed vs needs-parsing" rejection still stands (network cost, not
parse state, is the real axis), but the PR-count conclusion built on top of it
did not survive critique: the critic's recount put the true size at ~1700
lines (not ~900), found that a rendering-only split *is* live-verifiable
(contrary to the claim below), and surfaced three concrete defects (C1–C3,
§7a) that are cheaper to isolate in their own PR than to mix into the
mechanical ecosystem wiring. **Actual split: PR1 = T1 (minus live-reload) + T2
+ Ch2 rendering only; PR2 = Ch1 widening + did_change_configuration + C1–C3
fixes.** Original text follows, unchanged:

Recommendation: one PR, not two. The spec's Open Question proposes splitting
along "already-parsed (FR-008)" vs "needs parsing (FR-007)". Reject that axis —
live verification shows it does not correlate with anything that matters:
Cargo/PyPI/Composer are *not* pre-parsed yet are free, while Maven/Go *are*
pre-parsed yet are dead or partial. The meaningful axis is **network cost**, and
every zero-cost ecosystem belongs in v1 together. Splitting T1+T2 into their own
PR would ship a foundation with zero user-visible behavior, which cannot satisfy
NFR-006's live-verification gate. Estimated total ≈ 900 lines including tests —
large but reviewable. Fallback if the reviewer objects: PR1 = T1+T2, PR2 = T3+T4.

**Follow-up issues to file (one per deferred ecosystem, each carrying its own
cost decision):**
- npm — full packument is 2.37× the abbreviated one; a product tradeoff needing
  user input, not an engineering default.
- Maven/Gradle — solrsearch `core=gav` returns per-GAV `timestamp` as unix
  millis (matching the existing dead `Option<u64>` field's type); extra request.
- NuGet — requires resolving `RegistrationsBaseUrl` and paging the registration
  hive.
- Swift — GitHub tags carry no dates; needs the releases API (misses tag-only
  packages) or N commit lookups against an already rate-limited endpoint.
- Go Ch2 — `/@v/list` has no dates; would need one `.info` request per version.
- Cleanup: delete the dead `MavenVersion.timestamp` field.

---

## 7. Open questions — resolved, and gaps needing sign-off

### Resolved here
| Spec question | Decision |
|---|---|
| UX treatment | hover: age suffix + blockquote callout; diagnostics: message-only, severity unchanged at `HINT`; completion: `label_details` age, no cooldown verdict (§4) |
| Where cooldown is configured | `DepsConfig.freshness` via `initializationOptions`, 3-day default, clamped 0..30 d; live-reloadable via `did_change_configuration` (§2.1) |
| Trait signature / date crate | `fn published_at(&self) -> Option<PublishTime>` with a `deps-core` newtype over `i64` Unix seconds; `time 0.3` in `deps-core` only — ecosystem crates never touch a date crate |
| Clock skew | clamp age to 0 → "just now", counts as within cooldown |
| Cooldown boundary | `age < cooldown` (exclusive), documented once, uniform |
| Does freshness apply to the locked/installed version? | **No.** Only the recommendation target (`**Latest**`) and the version list. Lockfiles carry no timestamps, and a pinned version's age is not actionable. The `**Current**:` line is untouched |
| Swift non-GitHub hosts | moot — Swift is deferred entirely; the GitHub tags API has no dates for *any* host |
| FR-007/FR-008 PR split | rejected as an axis; split by network cost instead (§6) |
| OSV/002 coordination | out of scope; noted only |

### Decision record — G1–G6, all resolved 2026-08-23

| # | Item | Decision |
|---|---|---|
| **G1** | New `time` dependency | **Proceed.** Developer must run a context7 version check before adding it to `Cargo.toml` (project policy) — `0.3.55` above is an observation, not an instruction |
| **G2** | v1 ships 6 ecosystems, not 10–11 | **Confirmed.** npm, Maven/Gradle, NuGet, Swift are out of this PR; team-lead files one follow-up issue per ecosystem after it lands, using the cost findings in §0. Spec's Current State / NFR-001 / SC-001 updated accordingly |
| **G3** | FR-008 unsatisfiable for Maven, partial for Go | **Confirmed** as part of G2. Spec FR-007/FR-008 restated around network cost |
| **G4** | Pre-1.0 breaking struct changes | **Pre-approved** by standing policy (CLAUDE.md: no backward-compat concerns before v1.0.0). No further sign-off needed |
| **G5** | Config live-reload | **Reversed — now IN SCOPE.** `did_change_configuration` is implemented in this PR (§2.1), not deferred. Acceptance bar: changing `freshness.cooldown_secs` takes effect without an editor restart |
| **G6** | Ch1 `DocumentState`/`VersionData` widening | **Architect/developer's call** — proceed as designed (§4.1) |

US-004 note carried forward: cross-ecosystem consistency holds for *rendering*
(one implementation in `deps-core`, no `EcosystemFormatter` hook) but not for
*coverage*. The 5 deferred ecosystems fall back to US-003 graceful degradation,
which is byte-identical to pre-feature behavior.

### Adjacent bugs — dispositions confirmed
- Config silently discarded on deserialize error (`server.rs:236`) — **bundled
  here** as the shared `parse_config` helper (§2.1), since this PR touches config
  and adds a field that widens the blast radius. **Now PR2-only — see §7a C2.**
- `DiagnosticsConfig::{outdated,unknown,yanked}_severity` are parsed then dropped
  at `handlers/diagnostics.rs:15` (`_config`) — **out of scope**; team-lead files
  a separate issue. Do not wire them while implementing §4.3.

## 7a. Critic findings (2026-08-23) — three confirmed defects, PR split final

Critic verdict: core design (`PublishTime`, trait default, v1 scope) is sound.
Three defects confirmed against source (not inferred) block T1 as originally
scoped; user confirmed the 2-PR split as the resolution (below), superseding
§6's "one PR" recommendation.

### Confirmed blockers

| # | Defect | Where | Fix | PR |
|---|---|---|---|---|
| **C1** | `did_change_configuration` activates a latent deadlock: `server.rs:166` holds a `config.read()` guard across a loop that calls into `ensure_document_loaded` → `config.read()` (`lifecycle.rs:699`) — nested read on one write-preferring tokio `RwLock`, same task. Harmless today (only `write()` call is in `initialize`, before any requests); the new handler makes a concurrent `write()` reachable, which can permanently block the inner read | `server.rs:166` | Snapshot-and-drop the guard before the loop, matching the existing pattern at `:386`/`:432` (2-line fix) | **PR2** — only reachable via `did_change_configuration` |
| **C2** | The "malformed payload keeps previous config" guard in §2.1 does not fire: `DepsConfig` is all-`#[serde(default)]`, so a section-wrapped payload (e.g. `{"deps-lsp": {...}}`, which real clients send) deserializes *successfully* into an all-defaults struct — the `Err` arm never triggers, so the user's entire configuration is silently replaced with defaults. Data-loss bug, not a half-implementation | `parse_config` helper (§2.1) | Add a positive-signal check: reject/unwrap based on a known top-level key rather than trusting `Result::is_ok` | **PR2** — `parse_config`/`did_change_configuration` don't exist until PR2 |
| **C3** | The Ch1 "parallel map" (§4.1) desyncs: `lifecycle.rs:272` overwrites `cached_versions` with lockfile-resolved versions for instant display, but `preserve_cache` carries the *old* `published_at` map forward unchanged. Result: hover's `**Latest**` line can show `<locked version> (published 2 hours ago)` where the age belongs to a different version entirely. Silent, timing-window-only, invisible to unit tests | `lifecycle.rs:272` + all mirror sites of `cached_versions` mutation (6 total) | Replace the two parallel maps with one `HashMap<String, LatestVersion { version, published_at }>` so version and age can never drift apart | **PR2** — only affects Ch1 (diagnostics + `**Latest**` line), which is entirely PR2 scope |

### Plan corrections (non-blocking, apply wherever the relevant work lands)

- **M1** — §2's "only two entry points" undercounts diagnostics: `generate_diagnostics_internal(state, uri)` carries no config and has 4 call sites (3 background spawns in `lifecycle.rs`); `ServerState` holds no `DepsConfig` today. Threading `FreshnessSettings` through diagnostics is more than the table implies. (Confirmed accurate: `generate_hover`/`generate_diagnostics` have zero ecosystem overrides.) — **PR2**
- **M2** — diagnostics are push *and* pull (`client.publish_diagnostics` at `server.rs:182`, plus 3 lifecycle background spawns); `workspace/diagnostic/refresh` only reaches pull-capable clients, so §2.1's refresh nudge does not cover push-only clients. Document this as a known v1 gap in spec §1 non-goals rather than silently under-covering it. — **PR2**
- **M3** — clients gate `didChangeConfiguration` notifications on `workspace.didChangeConfiguration.dynamicRegistration`; without `client.register_capability` in `initialized` (~10 lines, available in `tower-lsp-server` 0.23) some clients never send the notification, making FR-012 unverifiable under NFR-006's live gate. Add the ~10-line registration alongside §2.1. — **PR2**
- **M4** — render helpers must take `now: PublishTime` as a parameter rather than calling `PublishTime::now()` internally; otherwise bucket-boundary assertions are wall-clock dependent and a single request can straddle a boundary between hover and diagnostics. — applies to **both PRs** (any code computing age from `published_at()`)

### `PublishTime` nits (apply in T1, PR1)

- `age_secs_from` as `const fn` overflows at `i64::MIN`; use `saturating_sub(...).max(0)` instead of raw subtraction.
- `is_within_cooldown(age_secs: u64, cooldown_secs: u64)` has two swappable same-typed params — mild inconsistency with the newtype direction from #191/#200, but not worth a wrapper type for two call sites. Document parameter order clearly in the doc comment instead.

### Final PR split (supersedes §6)

**PR1 — mechanical, fully live-verifiable, low risk:**
- T1 minus §2.1 (no `did_change_configuration`, no `parse_config` helper, no live-reload) — just `freshness.rs`, `Version::published_at`, `impl_version!` second arm, `FreshnessConfig`/`FreshnessSettings` (config field exists and is read at `initialize` as today; just not live-reloadable yet).
- T2 — all 6 ecosystem wiring subtasks (cargo, pypi, composer, bundler, dart, go-partial).
- Ch2-only rendering — hover's "Recent versions" list ages (§4.2b) and completion's `label_details` age (§4.4). **No** Ch1 widening, **no** `**Latest**` age/callout, **no** diagnostics changes.
- Apply the `PublishTime` nits and M4 (inject `now`) here.
- Live-verifiable per NFR-006 on the 5 full ecosystems + Go's Ch2 path (hover/completion only).

**PR2 — risk-isolated, built on PR1:**
- Ch1 widening (§4.1: `LatestVersions`/`DocumentState`/`VersionData.published`) using the corrected single-map design from C3, not the original parallel-map design.
- Hover's `**Latest**` age + cooldown callout (§4.2a), diagnostics message differentiation (§4.3).
- `did_change_configuration` (§2.1) + `parse_config` helper, with C1 (deadlock), C2 (config-loss), and M2/M3 (refresh coverage, dynamic registration) all fixed as part of this work, not deferred further.
- Update spec §1 to state the push-only/no-dynamic-pull-form boundary explicitly as a non-goal (per critic's did_change_configuration verdict: "push-only is an acceptable v1 boundary; the silence about it is not").

Both PRs target branch `feat/145-release-freshness-signal`; PR1 merges first, PR2 branches from post-merge `main` (or is rebased onto it) and closes issue #145. PR1 alone does not close the issue.

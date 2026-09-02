---
aliases:
  - Maven/Gradle Release-Freshness Plan
tags:
  - sdd
  - plan
  - deps-maven
  - deps-gradle
created: 2026-08-24
status: draft-pending-signoff
parent: "[[004-release-freshness-signal/plan]]"
issues: [221, 225]
---

# Implementation Plan: Release-Freshness for Maven/Gradle (issues #221, #225)

Addendum to `plan.md`. Covers the Maven/Gradle ecosystem deferred in §0/§6 of the
parent plan, plus the `MavenVersion.timestamp` dead-field cleanup (#225).

## 0. Current state (verified 2026-08-24 against `main` @ 592d3074)

PR1 of #145 has landed. Confirmed present:

| Item | Location |
|---|---|
| `Version::published_at() -> Option<PublishTime>` (default `None`) | `crates/deps-core/src/registry.rs:218` |
| `PublishTime` (+ `parse_rfc3339`, `from_unix_millis`, `age_secs_from`) | `crates/deps-core/src/freshness.rs:70-121` |
| `FreshnessSettings { enabled, cooldown_secs }` (`Copy` DTO) | `crates/deps-core/src/freshness.rs:269` |
| `FreshnessConfig` → `to_settings()`, `enabled` default **`true`** | `crates/deps-lsp/src/config.rs:489,523` |
| Ch2 rendering: hover age suffix | `crates/deps-core/src/lsp_helpers.rs:983` (`version_age_suffix`) |
| Ch2 rendering: completion `label_details` | `crates/deps-core/src/completion.rs:547-554` |

Confirmed **absent** (PR2 of #145, not yet landed — out of this scope):
`did_change_configuration`, `parse_config`, Ch1 widening (`LatestVersions`,
`DocumentState.latest_published_at`, `VersionData::with_published`), the
`**Latest**` age line, the cooldown callout, diagnostics differentiation.

**Scope consequence:** this work targets **Ch2 only** — hover's "Recent versions"
list and completion items. That is exactly the surface PR1 shipped for the other
six ecosystems, so Maven/Gradle reach parity with them and nothing more. When PR2
lands, Maven/Gradle inherit Ch1 for free *only* if PR2's `get_latest_matching`
path is also wired (see §7 OQ3).

### Registry sharing: `deps-gradle` inherits automatically

`deps-gradle` re-exports the type (`crates/deps-gradle/src/types.rs:6`:
`pub use deps_maven::MavenVersion as GradleVersion;`) and constructs its **own**
instance of the same registry type (`crates/deps-gradle/src/ecosystem.rs:23`:
`registry: Arc::new(MavenCentralRegistry::new(cache))`). There is exactly one
`impl Version for MavenVersion` (`crates/deps-maven/src/types.rs:93`) and one
`impl Registry for MavenCentralRegistry` (`crates/deps-maven/src/registry.rs:336`).

→ **No `deps-gradle` source changes are required.** Both ecosystems already route
`FreshnessSettings` into `complete_versions_generic`
(`deps-maven/src/ecosystem.rs:123-130`, `deps-gradle/src/ecosystem.rs:42-49`) and
neither overrides `generate_hover`, so both use `lsp_helpers::generate_hover`.
`deps-gradle` needs only a `CHANGELOG`/README mention and live verification.

---

## 1. Data source — **solrsearch rejected, repo1 directory listing recommended**

Issue #221 names Maven Central's `solrsearch?core=gav` endpoint. Live probing
(2026-08-24, 24 requests) says do not build on it.

### 1.1 Measurements

| Source | Success rate | Latency (ok) | Payload (guava, 150 vers.) | Conditional GET | androidx | Gradle Plugin Portal |
|---|---|---|---|---|---|---|
| `search.maven.org/solrsearch/select?core=gav` | **6/12** and **6/12** in two runs (~50%) | 0.23–0.68 s | 53 KB | none observed | **`numFound: 0`** | indexed (77 GAVs) |
| `repo1.maven.org/maven2/{g}/{a}/` (HTML listing) | **12/12** | **0.05–0.07 s** | 21 KB (44 KB for spring-core, 339 dirs) | **`Last-Modified` → 304 verified** | 404 | listing exists, **no dates** |

Failures on solrsearch were silent 10 s read timeouts, not `429` — consistent with
undocumented per-IP throttling. A ~50% failure rate on an interactive hover path
is disqualifying: the feature would appear and disappear at random, which reads as
a bug rather than as graceful degradation.

### 1.2 Correctness cross-check

`com.google.guava:guava:33.4.8-jre`
- solrsearch `timestamp: 1744651522422` → `2025-04-14 17:25:22 UTC`
- directory listing → `2025-04-14 17:25`

The listing is **UTC, minute precision, truncated** (not rounded). `format_relative_age`'s
smallest bucket is minutes, so the ≤59 s of lost precision is invisible at every
rendered bucket boundary. 158 of 159 anchors carry a date; the only undated anchor
is `../`.

### 1.3 Recommendation

Use the **directory listing of whichever repository base actually served
`maven-metadata.xml`**, not a fixed host. This is the single most important
correctness detail of the design:

| Repo | Metadata source | Listing dates | Result |
|---|---|---|---|
| Maven Central (`repo1`) | ✅ | ✅ | ages rendered |
| Google Maven (`dl.google.com`) | ✅ | 404 | `published_at() == None`, unchanged behavior |
| Gradle Plugin Portal (fallback) | ✅ | listing has no date column | `published_at() == None`, unchanged behavior |

Deriving the listing URL from the winning metadata URL means a Google-hosted or
plugin-portal-only artifact never issues a doomed request against `repo1`.

Coverage is therefore **not** 100% of Maven/Gradle dependencies — Android/AndroidX
projects get no ages at all. This is US-003 graceful degradation, identical in
shape to Go's documented partial coverage, and must be stated in
`docs/ECOSYSTEM_GUIDE.md` rather than left implicit.

---

## 2. Config threading — **new defaulted `Registry` trait method** (recommended)

### 2.1 The constraint, restated precisely

`EcosystemRegistry` and all 11 ecosystems are built in `ServerState::new`
(`crates/deps-lsp/src/document/state.rs:440-446`) via
`register_ecosystems(&registry, cache)` (`crates/deps-lsp/src/lib.rs:205-217`),
whose `register!` macro (`lib.rs:25-30`) calls `$ecosystem::new(Arc::clone($cache))`
uniformly. `DepsConfig` is a *separate* `Arc<RwLock<_>>` on `Backend`
(`crates/deps-lsp/src/server.rs:36`), first populated at `initialize`
(`server.rs:282`) — i.e. **after** every registry already exists.

But the settings already reach `deps-core` per request: PR1 threaded
`FreshnessSettings` into `Ecosystem::generate_hover`/`generate_completions`, and
both `deps-core` functions that fetch versions for a *freshness-rendering* surface
already hold it in scope:

- `lsp_helpers::generate_hover(..., freshness)` → `registry.get_versions(...)` at `lsp_helpers.rs:1008`
- `completion::complete_versions_generic(..., freshness)` → `registry.get_versions(...)` at `completion.rs:781`

### 2.2 Design

Add one defaulted method to the `Registry` trait (`crates/deps-core/src/registry.rs`):

```
fn get_versions_with<'a>(&'a self, name, freshness: FreshnessSettings)
    -> BoxFuture<'a, Result<Vec<Box<dyn Version>>>>
{ self.get_versions(name) }        // default: ignore, existing behavior
```

`MavenCentralRegistry` is the only override. Exactly two call sites switch to it —
`lsp_helpers.rs:1008` and `completion.rs:781` — and both already have the value.

**`generate_code_actions` (`lsp_helpers.rs:1301-1357`) deliberately keeps plain
`get_versions`.** It has no `freshness` parameter and renders no ages, so it must
never pay for the listing fetch. The two-method split makes that correct by
construction rather than by remembering to pass `enabled: false`.

### 2.3 Why this over the alternatives

| Option | Verdict |
|---|---|
| **A. `Arc<AtomicBool>` into `MavenCentralRegistry::new`** | Rejected. Requires plumbing the cell through `ServerState::new` → `register_ecosystems` → the `register!` macro → **all 11** `Ecosystem::new` signatures, for one ecosystem's benefit. Carries only `enabled`, not `cooldown_secs`, so it is a bespoke half-DTO that diverges from `FreshnessSettings` the moment a second field matters. Introduces shared mutable state where none exists today, and a second writer that PR2's `did_change_configuration` must remember to update — a silent-staleness bug waiting to happen. |
| **B. Change `Registry::get_versions` for all 11** | Rejected. 10 registry files + their doctests and tests churn so 9 ecosystems can ignore the parameter forever. The defaulted-method variant buys identical type safety for ~10 lines. (Pre-1.0 means this is *allowed*, not that it is *warranted*.) |
| **C. Defaulted `get_versions_with`** ✅ | Additive and object-safe (`FreshnessSettings` is `Copy + 'static`). Zero changes to 10 registries, to `register!`, to any `*::new`. Follows the precedent this codebase set twice already: `Registry::select_latest_matching` (#256) and `Version::published_at` (#145) are both defaulted opt-in trait methods. |

**Live reload is free.** Because the value is read per request from the
`Arc<RwLock<DepsConfig>>` snapshot in `handlers/hover.rs` / `handlers/completion.rs`,
Maven/Gradle pick up a changed `freshness.enabled` the instant PR2's
`did_change_configuration` lands — with no additional wiring, and without
introducing any new lock or the C1 nested-read deadlock class described in
parent-plan §7a.

---

## 3. Fetch and attach — `deps-maven` internals

### 3.1 Flow

```
Registry::get_versions_with(name, freshness)              [maven, NEW override]
 └─ get_versions_typed_with(name, freshness.enabled)      [NEW pub method]
     ├─ get_metadata(name) -> (versions, release, base)   [1 req — EXISTING, +1 return value]
     ├─ if enabled && base is Some:
     │     fetch_publish_times(base) -> HashMap<String, PublishTime>   [1 req — NEW, GATED]
     │       └─ any Err / non-200 / unparseable → empty map, tracing::debug!, never propagates
     ├─ for v in &mut versions { v.published_at = map.get(&v.version).copied() }
     └─ move_release_to_front(&mut versions, release)      [EXISTING]

Registry::get_versions(name)  →  get_versions_typed(name)  →  byte-identical to today
Registry::get_latest_matching →  untouched (Ch1, see §7 OQ3)
```

### 3.2 `get_metadata` must return the winning base URL

`crates/deps-maven/src/registry.rs:148-169` loops over `metadata_urls(name)` and
returns on the first `Ok`, discarding *which* URL won. Change its return type to
`(Vec<MavenVersion>, Option<String>, Option<String>)` — or better, a small private
struct — carrying the base directory of the successful fetch (the metadata URL
minus the trailing `maven-metadata.xml`). `get_versions_typed` and
`get_latest_matching_typed` (`registry.rs:171-188`) ignore the new field.

### 3.3 Listing parse

Line-oriented, no new dependency. For each line, require **both** an anchor
`<a href="{v}/"` and a trailing `YYYY-MM-DD HH:MM` on that same line; a line with
only one of the two yields nothing. This is what makes the parser safely return an
empty map for the Gradle Plugin Portal's dateless `<pre><a href="X/">X/</a></pre>`
format instead of guessing.

Date → `PublishTime` **without new deps and without new `deps-core` API**: build
`"{date}T{time}:00Z"` (`2011-09-28` + `16:04` → `2011-09-28T16:04:00Z`) and pass it
to the existing `PublishTime::parse_rfc3339`. `time`'s RFC 3339 parser validates the
field ranges, so a malformed line rejects rather than producing a bogus instant, and
NFR-005 ("all date parsing goes through `time`") holds. `deps-maven` gains no
`regex`, no `time`, no `chrono`.

Bound the work: the listing is capped by `HttpCache`'s `MAX_RESPONSE_BYTES` already;
the parse is a single pass. Largest observed real payload is 44 KB / 339 entries.

### 3.4 Failure and caching behavior

- Listing request fails, times out, 404s, or parses to nothing → every
  `published_at()` is `None`; the version list is returned in full, unchanged.
  The listing fetch is **never** allowed to fail `get_versions_with`.
- `HttpCache::get_cached` handles the listing like any other URL. `Last-Modified`
  is present and `304` was verified, so a repeat hover on the same artifact costs
  a conditional request, exactly like `maven-metadata.xml` beside it.
- Cache key is the URL, and the listing URL differs from every existing URL, so
  no cache-key collision (`cache.rs:168-176` contract).

---

## 4. `MavenVersion.timestamp` — resolving #225

`crates/deps-maven/src/types.rs:44-48`, currently `pub timestamp: Option<u64>`,
never read, `None` at both construction sites.

**Replace with `pub published_at: Option<PublishTime>`** and implement

```
fn published_at(&self) -> Option<PublishTime> { self.published_at }
```

on `impl deps_core::Version for MavenVersion` (`types.rs:93-114`).

Rationale: matches the field name and eager-parse rule the parent plan §3 applied
to all six landed ecosystems (`created_at`/`published`/`time` → `published_at:
Option<PublishTime>`), so Maven does not become the one ecosystem storing a raw
integer. Pre-1.0 → rename freely, record as a breaking change (parent plan §7a G4).

Blast radius is contained: 29 construction sites, **all inside `deps-maven`**
(3 in `types.rs`, 26 in `registry.rs`, nearly all `timestamp: None` in tests).
`deps-gradle` constructs none. Mechanical rename.

**Related dead code to resolve in the same PR:** `PublishTime::from_unix_millis`
(`freshness.rs:91`) is documented as "kept for a future ecosystem whose registry
reports millisecond timestamps (e.g. Maven's solrsearch `core=gav`)". If §1.3 is
accepted, that method has no caller and its doc comment names an approach the
project rejected. Either delete it (same dead-code class as #225 itself) or
rewrite the comment — do not leave it citing a rejected design. Recommend
deletion; it is trivially re-addable.

---

## 5. Files touched

| File | Change |
|---|---|
| `crates/deps-core/src/registry.rs` | + defaulted `Registry::get_versions_with` (~12 lines incl. docs) |
| `crates/deps-core/src/lsp_helpers.rs:1008` | `get_versions` → `get_versions_with(dep.name(), freshness)` |
| `crates/deps-core/src/completion.rs:781` | same, in `complete_versions_generic` |
| `crates/deps-core/src/freshness.rs:74-93` | delete `from_unix_millis` (or fix its doc) — see §4 |
| `crates/deps-maven/src/types.rs` | `timestamp: Option<u64>` → `published_at: Option<PublishTime>`; `impl Version::published_at` |
| `crates/deps-maven/src/registry.rs` | `get_metadata` returns winning base; new `fetch_publish_times` + listing parser; new `get_versions_typed_with`; `impl Registry::get_versions_with`; ~26 test construction sites renamed |
| `crates/deps-gradle/**` | **none** (inherits) |
| `CHANGELOG.md` | `[Unreleased]`: feature + breaking field rename + `from_unix_millis` removal |
| `docs/ECOSYSTEM_GUIDE.md` | freshness coverage row: Central ✅ / Google Maven ✗ / Plugin Portal ✗ |
| `crates/deps-maven/README.md`, `crates/deps-gradle/README.md` | brief mention if they document version metadata |

Estimated ~250 lines including tests. No new workspace or crate dependency.

## 6. Test plan

- **Listing parser** (pure, no network): real `repo1` fixture (guava excerpt, incl.
  the `r03`-style legacy dirs and the `../` anchor); Gradle Plugin Portal dateless
  fixture → empty map; malformed date (`2011-13-45 99:99`) → that entry absent, the
  rest still parsed; HTML with no `<pre>` at all → empty map; empty body → empty map.
- **Gating** (`mockito`): `enabled: false` → mock asserts the listing endpoint gets
  **zero** hits and every `published_at()` is `None`; `enabled: true` → one hit,
  timestamps attached to the matching versions.
- **Degradation** (`mockito`): listing returns 404 / 500 / times out → the version
  list is still complete and correctly ordered, all `published_at()` are `None`,
  no error surfaces.
- **Version/date pairing**: a listing containing a version absent from
  `maven-metadata.xml` and vice versa → no panic, no cross-assignment; ordering
  after `move_release_to_front` is byte-identical to the pre-feature output
  (FR-006 regression guard).
- **`deps-gradle`**: one test asserting `GradleVersion::published_at()` is wired,
  since it inherits rather than implements.
- **Live (NFR-006, blocking)**: `pom.xml` and `build.gradle.kts` each with (a) a
  Central artifact with a release in the last ~72 h, (b) an `androidx.*` artifact,
  (c) a Gradle plugin resolved via the portal fallback. Verify (a) renders ages and
  (b)/(c) render exactly as before. Record in `.local/testing/coverage.md` and a
  `journal/ci-NNN.md` entry.
- **Full gate**: `cargo +nightly fmt --all -- --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace
  --all-features --no-fail-fast`, rustdoc gate.

## 7. Open questions — need sign-off before implementation

- **OQ1 (blocking) — data source reversal.** Issue #221 specifies solrsearch. §1
  measures it at ~50% silent-timeout failure and zero coverage for Google Maven,
  and finds the `repo1` directory listing strictly better on every axis
  (reliability 12/12, ~7× faster, cache-validated, same host as the metadata fetch).
  Recommend switching, and editing #221 to record why. Only `fetch_publish_times`'
  internals differ if the team insists on solrsearch — the rest of this plan is
  source-agnostic — but the parse would then need `serde` structs instead of the
  line scanner, and `from_unix_millis` would stay alive.
- **OQ2 (decision point) — `freshness.enabled` defaults to `true`
  (`config.rs:489`),** so by default every Maven/Gradle **hover and version
  completion** issues one extra request. It is the same CDN host already being hit,
  ~60 ms cold and a 304 warm, and it does **not** touch document-open/diagnostics
  (Ch1 is untouched). Recommend **keeping the default `true`**: it gives Maven and
  Gradle the same out-of-the-box behavior as the other six ecosystems (US-004), and
  `freshness.enabled: false` is the documented opt-out. The alternative — a
  Maven-specific `freshness.maven_publish_times` defaulting to `false` — violates
  FR-010 ("uniform, no per-ecosystem override") and is not recommended.
- **OQ3 (scope boundary) — Ch1.** `get_latest_matching` is deliberately left alone,
  so when PR2 of #145 lands, hover's `**Latest**` line and the cooldown callout will
  show **no** age for Maven/Gradle even though the "Recent versions" list below does.
  Confirm this asymmetry is acceptable for now (it mirrors Go's documented Ch1/Ch2
  split), or fold a `get_latest_matching_with` into PR2 instead.
- **OQ4 (minor)** — the parent plan's follow-up list (§6) still says "Maven/Gradle —
  solrsearch … extra request" and "Cleanup: delete the dead `MavenVersion.timestamp`
  field" as two separate items. This plan merges them, which is what #225 asks for.
  Confirm #225 is closed by this PR rather than by a separate deletion.

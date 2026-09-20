# Maven & Gradle

Gradle resolves coordinates against the same Maven Central registry client Maven uses (falling
back to the Gradle Plugin Portal for a group ID not found there), so most of Maven's behavior —
version comparison, range matching, freshness — applies identically to both ecosystems. This
chapter documents them together; ecosystem-specific notes are called out where they diverge.

## Non-Registry Dependency Sources (Maven)

A Maven `<dependency>` with `<scope>system</scope>` and a `<systemPath>` — an explicit
locally-provided JAR, never resolved from Maven Central — is classified as a non-registry
dependency instead of defaulting to Maven Central. A dependency resolved this way is never
sent to Central, drops its public-registry hover link, and is excluded from OSV
vulnerability scanning against the public artifact coordinates (resolves #1202). A
system-scope dependency with a missing or empty `<systemPath>` still falls back to
Central-resolvable, since scope alone isn't a locally-provided binding without a path.

**Gradle**: Gradle has no per-dependency local-source syntax analogous to Maven's
`systemPath` today (`project(":core")`/`files()`/`fileTree()` dependencies are deliberately
not surfaced as version-checkable dependencies at all, so no Gradle dependency currently
carries a local source through this pipeline) — tracked as a follow-up, since Gradle 6+'s
`content { includeGroup(...) }` repository filtering is a static per-group binding this
project doesn't yet read.

## Version Comparison

Versions are now ranked with correct Maven semantics:
- **Numeric segments outrank non-numeric qualifiers**: `33` > `r09` (previously the reverse)
- **Prerelease qualifiers sort below their base release**: `1.0-RC1` < `1.0` (previously the reverse)
- **Qualifier precedence**: `alpha` < `beta` < `milestone` < `rc`/`cr` < `snapshot` < `release` < `sp` (case-insensitive)
- **Numeric suffixes within qualifiers are compared numerically**: `M10` > `M2` (previously `M2` > `M10`)

These fixes ensure hover's "Recent versions" list and completion sort order match Maven's actual version ordering.

## Version Range Matching

`version_satisfies_requirement` recognizes bracket-interval range syntax instead of only exact string equality, so a dependency pinned to a range no longer always renders as "outdated":

- **Maven** (`pom.xml`): interval notation — `[1.0,2.0)`, `[1.0]` (exact pin), `[1.5,)`, `(,2.0]` — and top-level comma unions, e.g. `(,1.0),(1.2,)`. Bounds are compared with Maven's qualifier-aware ordering, so `[1.0-beta,2.0-rc)` orders correctly. A bare, non-bracketed requirement (`1.0`) is still Maven's "soft" recommended version and compared for plain equality, not as a range.
- **Gradle** (`build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml`): the same bracket-interval syntax as Maven (no comma unions — Gradle's grammar doesn't have them), plus Gradle-specific forms: dynamic versions (`1.0+`, `2.10.+`), `latest.release`/`latest.integration` selectors, and Gradle's reversed-bracket exclusive notation (`]1.2,1.5]` for an exclusive lower bound, `[1.1,2.0[` for an exclusive upper bound).
- **Malformed input fails closed**: an unparseable range (unbalanced/stray brackets, an extra comma-separated component, a mismatched no-comma pin like `[1.0)`, or any unparseable member of a Maven union) is rejected as a whole — `version_satisfies_requirement` returns `false` rather than matching on a corrupted or partial parse.

## Unresolved Requirements

A requirement that couldn't be resolved to a concrete version (Maven's `${property}` missing from `<properties>`, Gradle's `$var`/`${var}` variable reference, or a Gradle version-catalog `version.ref` alias missing from `[versions]`) is treated as `RequirementStatus::Unresolved`, distinct from `UpToDate`/`Outdated`:

- **Diagnostics**: no "Newer version available" hint is shown — same as before, since the server can't verify either way.
- **Inlay hints**: no badge is shown at all, neither "up to date" nor "needs update" — showing "up to date" for a requirement that was never actually checked against the latest version would be misleading.
- **CodeLens "Update N outdated dependencies"** (see [Version
  Diagnostics](../cross-ecosystem/version-diagnostics.md#codelens-update-n-outdated-dependencies)):
  an unresolved requirement is also never counted or edited — it already fails the literal-span
  guard (the tracked span covers a placeholder/variable, not a version literal), so the two
  mechanisms agree independently rather than one depending on the other.

## Release-Freshness Coverage

Hover's "Recent versions" age suffix and completion's age `label_details` (gated by
`freshness.enabled`, default `true`) depend on Maven Central's `repo1.maven.org` HTML
directory listing, which is not available for every artifact source Maven/Gradle resolve
through:

- **Maven Central** (`repo1.maven.org`) — the directory listing is fetched and parsed;
  ages render normally.
- **Google Maven** (`dl.google.com`, `androidx.*`/`com.google.firebase.*`/
  `com.google.android.*`/`com.google.gms.*`/`com.android.*` group IDs) — the listing 404s
  for every artifact, so no extra request is even attempted; `published_at()` is always
  `None` and the version list itself is unaffected.
- **Gradle Plugin Portal** (`plugins.gradle.org`, the fallback for a group ID not found on
  Maven Central) — the listing has no date column; same result as above.

This is intentional graceful degradation (US-003), the same shape as Go's documented
partial freshness coverage (`/@v/list` carries no per-version dates either) — not a bug.

## License Hover (Gradle)

Gradle's license hover follows the Maven Central POM's `<parent>` coordinate chain when a
dependency's own POM declares no `<licenses>` block — see [License
Hover](../cross-ecosystem/licensing.md#license-hover) for the full cross-ecosystem picture and
the license policy diagnostic that consumes the same normalized data.

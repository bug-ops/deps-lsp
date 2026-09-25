# Typosquat Detection (issue #1437)

Flags a declared direct dependency whose name deps.dev reports as asymmetrically
similar to a much more popular package — a possible typo or a deliberate
typosquat (`crossenv` vs `cross-env`, `expres` vs `express`).

## How It Works

For a declared dependency in one of the seven [deps.dev](https://deps.dev)-covered
ecosystems (Cargo, npm, PyPI, Go, Bundler, Maven, NuGet), `deps-lsp` queries deps.dev's
v3alpha `GetSimilarlyNamedPackages` endpoint. That endpoint returns identity only — no
popularity data — so popularity is resolved separately via `GetPackage` (the package's
default version) and `GetDependents` (that version's dependent-package count), for both
the declared package and up to five similarity candidates.

A candidate fires the diagnostic only when **both** hold:

- its `dependentCount` is at least **50×** the declared package's own `dependentCount`
  (a threshold validated against real deps.dev data: confirmed historical typosquats
  score 300×-3000×, the closest known legitimate similarly-named pair,
  `coffee-script`/`coffeescript`, scores ~6.9×)
- its `dependentCount` is at least **50** in absolute terms, so two obscure packages
  can't trip the ratio on noise

Composer, GitHub Actions, GitLab CI/CD, Dart, Swift, Gradle, and Deno have no
[deps.dev](https://deps.dev) coverage and are never queried — not a deferred gap, deps.dev
does not track those package systems at all. Only manifest-declared **direct**
dependencies are checked, never transitive/lockfile-resolved ones.

## Behavior

- Renders as a single [`Severity::Hint`](../configuration.md#configuration-reference)
  diagnostic (code `typosquat-suspect`) naming the suspected-intended package — deliberately
  the weakest severity this project uses, since the similarity algorithm is an undocumented
  deps.dev black box, not a structured, confirmed finding like an OSV advisory or a license
  violation.
- Resolved via a background, per-document pre-fetch (mirroring the tier-3 license
  pre-fetch's design) — never blocks a hover or diagnostics response; a result that
  arrives after the initial diagnostics publish triggers its own follow-up publish.
- A dependency's name is only ever sent to deps.dev when its declared source is a public
  registry — a private-registry, git, or path dependency's name is never sent, and a
  dependency that switches to a non-public source after a signal was resolved stops
  rendering it immediately (re-checked at render time, no network call).
- Never wired into any rename/quickfix code action — the similarity signal is materially
  weaker evidence than the structured-registry-field bar
  [package-rename quickfixes](version-diagnostics.md) require.

## Configuration

Ships **disabled by default** — enable via `typosquat.enabled` (see the
[Configuration reference](../configuration.md#configuration-reference)). Unlike
`supply_chain`/`diagnostics.vulnerabilities_enabled` (both opt-out), this signal is built on
an undocumented, v3alpha (no stability guarantee) similarity algorithm, so it stays
opt-in-only at launch; default-on is deferred to a separate future issue once the endpoint
has shown stability across releases.

## Known Limitations

- A signal that fires once persists on that dependency until it's edited/removed or the
  document closes, even if a later re-check would no longer find the same candidate
  qualifying (e.g. the candidate's own popularity dropped). This is a deliberate trade-off
  for a `Hint`-severity, best-effort signal, not a bug.
- The similarity algorithm's exact matching logic is deps.dev's own, undocumented
  implementation detail — `deps-lsp` has no visibility into false negatives (a real
  typosquat deps.dev's algorithm simply doesn't surface as "similar").

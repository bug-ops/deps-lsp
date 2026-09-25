# Composer

## Basics

Composer manifests are `composer.json`, with dependencies under `require` (production) and
`require-dev` (development):

```json
{
  "require": {
    "symfony/console": "^7.0",
    "monolog/monolog": "~3.5"
  }
}
```

Platform packages (`php`, `ext-*`, `lib-*`) are filtered out — they name a PHP runtime or
extension, not a Packagist package, and have no registry entry to resolve. Every remaining
entry is resolved against **Packagist**'s metadata API
(`repo.packagist.org/p2/{vendor}/{package}.json`), with hover showing the latest version,
license, and (if the maintainer flagged the package) an "abandoned" notice. Completion queries
Packagist's `packagist.org/search.json` endpoint. Version constraints use Composer's own
syntax — caret (`^7.0`, compatible up to the next major), tilde (`~3.5`, compatible up to the
next minor), exact pins, and wildcards — compared with the stability-aware ordering described
below. When a `composer.lock` exists alongside the manifest, it is read to resolve each
dependency's actual in-use (installed) version, shown alongside the declared constraint.

## Version Comparison

`compare_versions` previously discarded everything after the first non-digit character in a
dot-separated segment, so a prerelease/qualifier version compared as *equal* to its stable
counterpart. Composer now applies proper stability-aware ordering: stability precedence `dev`
< `alpha` < `beta` < `RC` < `stable`, applied both to requirement-satisfaction comparison and
to "latest version" selection. `select_latest_matching`/`get_latest_matching` exclude
alpha/beta/RC releases by default (mirroring Composer's `minimum-stability: stable` default)
unless overridden; a wildcard/existence-check requirement still resolves a prerelease-only
package instead of reporting no version found. The effective stability floor is now manifest-
and dependency-aware: a per-dependency `@stability` flag (`^1.0@beta`) or a directly-pinned
prerelease version overrides the manifest's own `composer.json` `minimum-stability` field,
which in turn overrides the `stable` default — reflected consistently across diagnostics,
hover, completion, and code actions, via a shared `SelectionContext` rather than a
diagnostics-only path. Editing `minimum-stability` in an already-open document forces a full
re-fetch, so the other surfaces don't keep showing a stale "latest" behind the new stability
floor. Separator-less and dot/underscore-separated prerelease suffixes (`1.0.0RC1`,
`2.6.3.alpha`) classify consistently regardless of `v`/`V` prefix.

Composer's update code actions and completion also preserve the requirement's own `v`-prefix
style instead of forcing the raw Packagist tag's prefix onto an unprefixed requirement (or vice
versa).

See [Dart](dart.md#version-comparison) for the equivalent fix in that ecosystem, which shares
the same underlying `compare_versions` bug class and was corrected in the same change.

## Non-Registry Dependency Sources

A `require` entry bound to a non-`vcs`-heuristic `repositories` entry is classified as
non-registry instead of defaulting to Packagist: a `package`-type repository (matched by
its embedded `package.name`), an `artifact`-type repository, and an `only`/`exclude`
wildcard-filtered `vcs`/`path` entry (Composer's `*` glob syntax, not just exact names). A
top-level `{"packagist.org": false}` entry disables the default registry outright. A
dependency resolved this way is never sent to Packagist, drops its public-registry hover
link, and is excluded from OSV vulnerability scanning against the public package name
(resolves #1202).

A bare `vcs`/`path`/`artifact` repository entry with no `only` filter has no static
per-package name binding in `composer.json` itself (Composer tries every declared
repository, in order, for any required package) — an earlier vendor-substring URL heuristic
covered this case but produced false positives that silently disabled OSV scanning for
unrelated public packages sharing a GitHub org with a private repository's URL (e.g. one
`vcs` entry for `github.com/acme/internal` incorrectly reclassifying an unrelated public
`acme/`-scoped package too). The heuristic was removed rather than fixed. Instead, when a
bare repository of this kind is declared, an ancestor `composer.lock` (once `composer
install` has run) is cross-checked for the affected dependency's own recorded
`source.type`, and only `"path"` is trusted as a non-registry signal — never `"git"`, since
`composer.lock` records a `"git"` source for essentially every ordinary Packagist-resolved
package too (Packagist itself mirrors GitHub/GitLab/Bitbucket-hosted packages), so it cannot
distinguish a genuinely private package from an ordinary public one (resolves #1212).

**Known limitation**: the `vcs`-repository case from #1202's original report (a private
git-hosted package, no lockfile equivalent to Path's unambiguous signal) remains an accepted
gap, as does a lockless manifest (no `composer.lock` present) and the `artifact` repository
type (Composer's lock records an `artifact`-sourced package under `dist`, not `source`, so
this repository kind can never trigger the override).

## Deprecation & Abandoned Packages

Composer's `abandoned` field powers two cross-ecosystem features rather than a
Composer-specific one — see [Package Deprecation
Diagnostics](../cross-ecosystem/version-diagnostics.md#package-deprecation-diagnostics-issue-205)
for the diagnostic and the Composer-only "Replace with X" code action, and [Yanked Version
Diagnostic](../cross-ecosystem/yanked-and-vulnerabilities.md#yanked-version-diagnostic) for how
`abandoned` also feeds the yanked-version check (restricted to exact-pin requirements).

## Licensing

Composer's license arrives for free in its hot-path Packagist registry response, so it is
covered by both [License Hover](../cross-ecosystem/licensing.md#license-hover) and the
[License Policy Diagnostic](../cross-ecosystem/licensing.md#license-policy-diagnostic-issue-661)
with no dedicated pre-fetch.

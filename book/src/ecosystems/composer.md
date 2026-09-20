# Composer

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
which in turn overrides the `stable` default — reflected in the live "outdated" diagnostic,
not just available as a library-level API. Separator-less and dot/underscore-separated
prerelease suffixes (`1.0.0RC1`, `2.6.3.alpha`) classify consistently regardless of `v`/`V`
prefix.

**Known limitation**: editing `minimum-stability` alone in an already-open document does not
refresh already-fetched dependencies' cached "latest" version until the document is closed and
reopened.

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

**Known limitation**: a bare `vcs`/`path`/`artifact` repository with no `only` filter is
*not* classified — an earlier vendor-substring URL heuristic covered this case but produced
false positives that silently disabled OSV scanning for unrelated public packages sharing a
GitHub org with a private repository's URL (e.g. one `vcs` entry for
`github.com/acme/internal` incorrectly reclassifying an unrelated public `acme/`-scoped
package too). The heuristic was removed rather than fixed; this case is tracked as a
follow-up, likely via `composer.lock`'s already-parsed per-package `source.type` mapping
for the common case where a lockfile is present.

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

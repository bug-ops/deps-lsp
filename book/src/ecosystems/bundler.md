# Bundler

`deps-bundler` provides LSP support for Ruby projects using Bundler.

## Basics

| | |
|---|---|
| Manifest file | `Gemfile` |
| Lock file (in-use version) | `Gemfile.lock` |
| Registry | RubyGems (`rubygems.org/api/v1`) |
| Version syntax | RubyGems' own `Gem::Version`/`Gem::Requirement` semantics, ported directly from RubyGems' source so ordering and `~>` (pessimistic operator) matching are exact, including prerelease tie-breaking |

```ruby
gem "rails", "~> 7.1.0"
gem "pg"
```

Hovering a gem's version string shows the latest RubyGems release and a link to its
rubygems.org page; an outdated requirement gets an inlay hint and a diagnostic with an
"Update to latest version" code action. Both modern `key: value` and legacy hash-rocket
`:key => value` option syntax (`group:`, `require:`, `platforms:`, `source:`, `git:`,
`path:`) are recognized identically.

## Custom/Private Registries (issue #980)

Unlike [Cargo](cargo.md)/[npm](npm.md)/[PyPI](pypi.md)/[Go](go.md)/[NuGet](nuget.md), `deps-bundler`
and `deps-dart` do not fetch version data from a declared custom registry — they only *classify*
a dependency as `DependencySource::CustomRegistry` instead of `Registry` so it stops being queried
against the public registry under its real name and stops rendering a misleading public-registry
hover link.

**Bundler (`Gemfile`)**: a `source "<url>" do ... end` block (a comment after
`do` is tolerated), and the per-gem inline `source:`/`git:`/`path:` options
(modern `key:` and legacy hash-rocket `:key =>` forms both recognized — see
below), classify the gems they cover as `CustomRegistry`/`Git`/`Path` instead of
falling through to `Registry` and leaking the gem's name to rubygems.org. A gem
with no declared source still resolves against rubygems.org (`Registry`)
unchanged.

**Dart (`pubspec.yaml`)**: see [Dart](dart.md#customprivate-registries-issue-980) for the
equivalent `hosted:` classification.

**Known limitation**: neither ecosystem fetches version data from the declared
custom source — a `CustomRegistry` dependency gets no hover version list,
diagnostics, completion, or code lens, the same degraded-but-honest behavior a
declared-but-unqueried registry has always had, just now applied to the correct
dependencies instead of silently querying the wrong ones. `suppress_package_url`
(Bundler's `PackageRendering` impl) hides the rubygems.org hover link for any
non-`Registry` source, since rendering it would falsely imply the gem is
published there.

## Legacy Hash-Rocket Option Syntax (issues #987, #988, #990)

Ruby's older `:key => value` option syntax is now recognized everywhere the
modern `key: value` form already was — per-gem `source:`/`git:`/`path:`/`github:`
options (classification above), `group:`, `require:`, and `platforms:`. A gem
declared with hash-rocket syntax previously fell through to `Registry` (for the
routing options) or was silently dropped (for `group:`/`require:`/`platforms:`)
instead of being recognized. A left word boundary on the key match also stops
`subgroup:`/`autorequire:`-style keys from being mistaken for `group:`/`require:`.
`VERSION_PATTERN` additionally tolerates a trailing comment after the closing
quote (`gem "rails", "~> 7.0" # pinned`), so a version requirement is no longer
silently dropped just because the line ends with a comment.

## Yanked-Version Diagnostics

Bundler participates in the cross-ecosystem
[yanked-version diagnostics](../cross-ecosystem/yanked-and-vulnerabilities.md) for the
in-use-version check (sourced from RubyGems' `yanked` field), but RubyGems' `versions.json`
never includes a `yanked` field on any entry for the *range-requirement* check — see
[Yanked Version Diagnostic](../cross-ecosystem/yanked-and-vulnerabilities.md#yanked-version-diagnostic)
for the full per-ecosystem coverage table.

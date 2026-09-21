# Dart

`deps-dart` provides LSP support for Dart/Flutter projects using the Pub package manager.

## Basics

| | |
|---|---|
| Manifest file | `pubspec.yaml` |
| Lock file (in-use version) | `pubspec.lock` |
| Registry | pub.dev (`pub.dev/api/packages/{name}`) |
| Version syntax | SemVer 2.0.0, with §11 prerelease-precedence ordering (numeric identifiers compare numerically, alphanumeric compare lexically, a prerelease sorts below its base release) |

```yaml
dependencies:
  http: ^1.2.0
  provider: ^6.1.1
```

Hovering a package's version constraint shows the latest pub.dev release and whether the
constraint is satisfied; an outdated dependency gets an inlay hint and a diagnostic with an
"Update to latest version" code action. `dependencies`, `dev_dependencies`, and
`dependency_overrides` are all parsed, along with YAML anchor/alias-based section reuse (see
below).

## Custom/Private Registries (issue #980)

Unlike [Cargo](cargo.md)/[npm](npm.md)/[PyPI](pypi.md)/[Go](go.md)/[NuGet](nuget.md), `deps-dart`
does not fetch version data from a declared custom registry — it only *classifies* a dependency
as `DependencySource::CustomRegistry` instead of `Registry` so it stops being queried against the
public registry under its real name and stops rendering a misleading public-registry hover link.
See [Bundler](bundler.md#customprivate-registries-issue-980) for the equivalent `source "..."`
classification, which shares this same design.

A dependency's `hosted:` value — either the `hosted: <url>` shorthand or the
`hosted: {name, url}` map form — classifies it as `CustomRegistry`, mirroring Bundler's
`source "..."` and Cargo's `registry = "..."` handling (#248). An explicit `hosted:
https://pub.dev` (or its legacy `pub.dartlang.org` alias) is recognized as the *default*
registry and stays `Registry` rather than being misclassified as custom just because
`hosted:` was written out explicitly.

**Known limitation**: no version data is fetched from the declared custom source — a
`CustomRegistry` dependency gets no hover version list, diagnostics, completion, or code
lens, the same degraded-but-honest behavior a declared-but-unqueried registry has always
had, just now applied to the correct dependencies instead of silently querying the wrong
ones.

## Version Comparison

`compare_versions` previously discarded everything after the first non-digit character in a
dot-separated segment, so a prerelease/qualifier version compared as *equal* to its stable
counterpart (`2.0.0-beta1` tied with `2.0.0`). Dart now applies proper prerelease-aware
ordering: SemVer 2.0.0 §11 precedence — numeric identifiers compare numerically, alphanumeric
identifiers compare lexically (ASCII), and a version with a prerelease sorts below its base
release. Applied both to "latest version" selection (pub.dev's response order) and to
constraint matching, so hover/completion sort order and outdated diagnostics are both
corrected. See [Composer](composer.md#version-comparison) for the equivalent fix in that
ecosystem, which shares the same underlying bug class.

## YAML Anchor/Alias Resolution

`pubspec.yaml` supports YAML anchors (`&name`) and aliases (`*name`) for sharing structure
between sections, e.g. a shared `dependencies:` block reused via
`dev_dependencies: *shared_deps`. Aliasing an entire `dependencies:`/`dev_dependencies:`/
`dependency_overrides:` section, or an entire `environment:` mapping (not just its `sdk:`
value), resolves correctly — the aliased dependencies/`sdk:` constraint appear as if written
out in full, including when the same section is aliased more than once.

**Known limitation**: resolved-via-alias dependencies show no hover, diagnostics, completion,
inlay hints, or code lens, since no position in the aliasing occurrence's own text
corresponds to them (only the anchor's original definition does, which would be misleading
and — for a section aliased more than once — ambiguous). They still count toward the
document's dependency total (including the truncation cap), and are visible to anything
reading the parsed dependency list. A single dependency's own value aliasing a whole mapping
(`pkg: *shared_entry`, as opposed to the section or `environment:` key itself) is not
resolved at all — the dependency appears with a real name but no version/source info.

# Deno

`deps-deno` provides LSP support for Deno projects, which can depend on packages from two
different registries in the same `imports` map.

## Basics

| | |
|---|---|
| Manifest file | `deno.json` or `deno.jsonc` |
| Lock file (in-use version) | not yet supported — `deno.lock` parsing is a documented gap; no `LockFileProvider` is registered for this ecosystem |
| Registry | `jsr:` specifiers resolve against JSR (`jsr.io`/`api.jsr.io`); `npm:` specifiers resolve against the same npm registry client `deps-npm` uses |
| Version syntax | node-semver ranges, same as npm |

```json
{
  "imports": {
    "@std/fs": "jsr:@std/fs@^1.0.0",
    "lodash": "npm:lodash@^4.17.21"
  }
}
```

A dependency's scheme prefix (`jsr:` or `npm:`) determines which registry client serves its
hover, completion, and diagnostics — both schemes get the identical LSP experience version
data otherwise gets (outdated/unsatisfiable diagnostics, inlay hints, code actions), just
sourced from different upstream registries.

## Non-Registry Dependency Sources

A `deno.json`/`deno.jsonc` `imports` entry resolved to a private npm scope via `.npmrc` is
classified as a non-registry dependency instead of defaulting to `registry.npmjs.org`
(resolves #1202). This `.npmrc` resolution now shares npm's cached ancestor-config lookup
and live `RegistryAccessPolicy` instead of re-reading `.npmrc` from disk with a
hardcoded policy on every parse, and participates in the same live-config reparse scope as
npm — a `registries.workspace_registries` change reaches an already-open `deno.json` the
same way it reaches `package.json` (resolves #1212).

A scope-overridden `npm:` import is fully fetchable, not just correctly classified: hover,
diagnostics, completion, and inlay hints query the resolved alternate registry — the same
`deps-npm` registry client and fail-closed routing `package.json` uses for the identical
`.npmrc` entry — instead of silently behaving as an unresolved dependency (resolves #1227).

## Release-Freshness Coverage

`jsr:` specifiers get full freshness coverage at **zero extra request cost** — better than
both [NuGet](nuget.md#release-freshness-coverage) and [npm](npm.md#release-freshness-coverage).
JSR's `meta.json` (the same response `JsrRegistry::get_versions` already fetches for the
version list) carries a per-version `createdAt` timestamp, so `published_at` is populated
unconditionally with no separate fetch and no TTL to tune. `npm:` specifiers in `deno.json`
inherit npm's own freshness behavior exactly, since `DenoRegistry` delegates them to the same
`deps-npm` registry client `package.json` uses.

## Yanked Versions

`jsr:` specifiers get a genuine per-version yanked signal from JSR's `meta.json`; `npm:`
specifiers delegate to npm's own `deprecated`-sourced signal, including its restrictions — see
[Yanked Versions & Vulnerabilities](../cross-ecosystem/yanked-and-vulnerabilities.md) for the
full cross-ecosystem picture.

## Licensing

Deno's license comes from a per-ecosystem background pre-fetch (JSR's per-version `license`
field, `jsr:` specifiers only) rather than the hot-path registry response — see [License
Hover](../cross-ecosystem/licensing.md#license-hover) for the full cross-ecosystem picture.

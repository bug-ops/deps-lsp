# Deno

## Non-Registry Dependency Sources

A `deno.json`/`deno.jsonc` `imports` entry resolved to a private npm scope via `.npmrc` is
classified as a non-registry dependency instead of defaulting to `registry.npmjs.org`
(resolves #1202). **Known limitation**: unlike npm's own `.npmrc` handling, Deno's `.npmrc`
resolution is not yet wired into this project's shared ancestor-config-file cache — it
re-reads `.npmrc` from disk on every parse rather than reusing the cached lookup npm's
`NpmEcosystem::with_context` already benefits from; tracked as a follow-up.

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

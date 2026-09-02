# deps-github-actions

[![Crates.io](https://img.shields.io/crates/v/deps-github-actions)](https://crates.io/crates/deps-github-actions)
[![docs.rs](https://img.shields.io/docsrs/deps-github-actions)](https://docs.rs/deps-github-actions)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-github-actions)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

GitHub Actions workflow dependency support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It
provides parsing and registry integration for `.github/workflows/*.yml`/`*.yaml` files and
implements `deps_core::Ecosystem`.

## Features

- **Event-driven YAML parsing** — `yaml-rust2`'s `MarkedEventReceiver` API tracks every
  `uses:` step individually with its own position, so two occurrences of the same action
  pinned at different refs get distinct, independently editable ranges
- **Full pin-style coverage** — tag (`@v4`, `@v4.2.0`), commit SHA (`@<40hex>`, optionally
  annotated `# vX.Y.Z`), and branch (`@main`) refs, plus recognition (without version
  resolution) of local composite actions (`./local`), Docker image refs (`docker://...`),
  and reusable-workflow calls
- **GitHub tags API registry** — per-repository tag/commit-SHA cross-reference, with
  request coalescing so N workflows referencing the same action on a cold cache issue one
  fetch, not N, and a local rate-limit gate that stops hammering GitHub once a 403 is seen
- **SHA-pin-aware code actions** — updating a `@<sha> # vX.Y.Z` pin writes both a new SHA
  and its matching tag comment, never silently downgrading a SHA pin to a bare tag
- **Mutable-ref-pin security diagnostic** (issue #473) — a tag-pinned `uses:` step (e.g.
  `@v4`) gets an additive, independent diagnostic recommending SHA pinning, plus a "Pin to
  commit SHA" quick fix rewriting it to `@<sha> # <tag>` when the tag's commit is already
  known; on by default, configurable via `mutable_ref_pin_severity`/`mutable_ref_pin_enabled`
- **Release-freshness signal (partial)** (issue #486) — `GithubActionsRegistry::
  get_versions_with_release_dates`, invoked via `Registry::get_versions_with` when
  freshness rendering is enabled, attaches GitHub Release publish timestamps to
  tag-derived versions via the shared `deps_core::github::ReleaseDatesCache` (also used
  by `deps-swift`), memoized behind a TTL; requires `GITHUB_TOKEN` and covers only
  versions with a matching GitHub Release (see `ECOSYSTEM_GUIDE.md`)

## Installation

```toml
[dependencies]
deps-github-actions = "0.11"
```

> [!IMPORTANT]
> Requires Rust 1.91 or later.

## Usage

```rust
use deps_github_actions::{parse_workflow_yaml, GithubActionsRegistry};
use std::sync::Arc;

let result = parse_workflow_yaml(content, &uri)?;
let registry = GithubActionsRegistry::new(Arc::new(deps_core::HttpCache::new()));
```

## Pin contract

| `uses:` form | `version_range` spans | `version_requirement()` | `version_literal()` |
|---|---|---|---|
| `actions/checkout@v4` | `v4` | `v4` | `None` |
| `…@v4.2.0` / `…@4.2.0` | the tag | same | `None` |
| `…@<40hex> # v4.2.0` | `<40hex> # v4.2.0` | `v4.2.0` (from the comment) | the raw span |
| `…@<40hex>` (no comment) | `<40hex>` | `<40hex>` | `None` |
| `…@main` | `main` | `main` | `None` |
| `./local`, `docker://x:1`, a reusable-workflow call | `None` | `None` | `None` |

The SHA-with-comment row is load-bearing: the comment is treated as the declared intent
(Dependabot/Renovate always write it), so the shared "is this up to date" comparison works
against the tag with zero SHA-to-tag network resolution.

## Known limitations

- Bare SHA and branch refs have no resolvable version — no outdated diagnostic, no inlay
  hint, matching the existing Maven `${property}`/Gradle `$var` precedent for an
  unresolvable requirement
- Reusable-workflow calls (`owner/repo/.github/workflows/x.yml@ref`) are parsed and
  recognized but deliberately non-resolvable: the referenced workflow's version and the
  host repository's release tags are not reliably the same thing, and a wrong diagnostic
  on a supply-chain feature is worse than none
- The publish-date/freshness signal requires `GITHUB_TOKEN`: without it, the second
  `/releases` fetch is skipped and hover/completion omit publish ages (the tags fetch
  itself still works unauthenticated)
- Package-name completion is unimplemented (`search()` always returns empty): GitHub has
  no action-specific search endpoint cheaper than repository search, and querying it per
  keystroke would burn the 60 req/hour unauthenticated budget fast
- The unauthenticated GitHub API budget (60 req/hour) is per-IP and shared with any
  `deps-swift` traffic in the same process; set `GITHUB_TOKEN` to raise it to 5000 req/hour
- The "Pin to commit SHA" quick fix is withheld for a quoted `uses:` value
  (`uses: "actions/checkout@v4"`) — the ref sits inside the quotes there, and appending
  `# <tag>` would corrupt the value instead of adding a YAML comment; the diagnostic still
  fires, just without the automated fix

## License

[MIT](../../LICENSE)

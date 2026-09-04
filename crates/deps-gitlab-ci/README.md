# deps-gitlab-ci

[![Crates.io](https://img.shields.io/crates/v/deps-gitlab-ci)](https://crates.io/crates/deps-gitlab-ci)
[![docs.rs](https://img.shields.io/docsrs/deps-gitlab-ci)](https://docs.rs/deps-gitlab-ci)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-gitlab-ci)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

GitLab CI/CD `include:` dependency support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It
provides parsing and registry integration for `.gitlab-ci.yml` and `.gitlab/ci/*.yml`/
`*.yaml` files and implements `deps_core::Ecosystem`.

## Features

- **Two include forms** — `include: - project: org/proj` + `ref:` (a plain git ref,
  resolved against the GitLab repository-tags API) and
  `include: - component: host/org/proj/name@ref` (a CI/CD Catalog component pin, resolved
  against the **project releases** API — a component version *is* a Release, never a raw
  tag)
- **Event-driven YAML parsing** — `yaml-rust2`'s `MarkedEventReceiver` API tracks every
  `include:` entry individually with its own position, correctly scoping the top-level
  `include:` key across the multi-document `spec:` header form GitLab CI component files use
- **Self-hosted GitLab instance support** — an optional `registries.gitlab_instance_host`
  setting names the instance a host-less `project:` include and a `$CI_SERVER_FQDN`-relative
  `component:` include resolve against, and is the *one* host an optional `GITLAB_TOKEN`
  (via the `PRIVATE-TOKEN` header) is ever sent to — replacing, not joined with, `gitlab.com`
- **Full `component:` pin priority ladder** — commit SHA, exact release name, `~latest`
  (highest published non-prerelease release), and partial semver (`1.2`, `1`) via
  `semver::VersionReq` range matching, per GitLab's own documented CI/CD Catalog resolution
  order
- **Per-host rate limiting** — one self-hosted instance rate-limiting or requiring
  authentication never disables lookups against `gitlab.com` or any other configured host

## Installation

```toml
[dependencies]
deps-gitlab-ci = "0.12"
```

> [!IMPORTANT]
> Requires Rust 1.91 or later.

## Usage

```rust
use deps_core::net_policy::RegistryAccessPolicy;
use deps_gitlab_ci::{GitlabInstanceHost, GitlabCiEcosystem};
use std::sync::{Arc, RwLock};

let cache = Arc::new(deps_core::HttpCache::new());
let policy = Arc::new(RegistryAccessPolicy::default());
let gitlab_instance_host_raw = Arc::new(RwLock::new(None)); // or Some("gitlab.mycorp.dev".to_string())
let ecosystem = GitlabCiEcosystem::with_context(cache, policy, gitlab_instance_host_raw);
```

## Pin contract

| Include form | `pin` | Resolved against |
|---|---|---|
| `project: org/proj` + `ref: <40-hex sha>` | `PinStyle::Sha` | `/repository/tags` |
| `project: org/proj` + `ref: v1.2.3` (exact tag) | `PinStyle::Tag` | `/repository/tags` |
| `project: org/proj` + `ref: main` (branch) | `PinStyle::Branch` | not resolved |
| `project: org/proj` (no `ref:`) | `None` | not resolved |
| `component: host/org/proj/name@<40-hex sha>` | `PinStyle::Sha` | `/releases` |
| `component: host/org/proj/name@1.0` (exact release) | `PinStyle::Tag` | `/releases` |
| `component: host/org/proj/name@~latest` | `PinStyle::Latest` | `/releases` |
| `component: host/org/proj/name@1.2` (partial semver) | `PinStyle::Partial` | `/releases` |
| `component: host/org/proj/name@some-branch` | `PinStyle::Branch` | not resolved |

`include: - template: ...` and `include: - remote: ...` are recognized and skipped —
not version-pinnable. `image:`/`services:` Docker tags are out of scope entirely and never
parsed.

## Known limitations

- Only `.gitlab-ci.yml` and the `.gitlab/ci/*.yml`/`*.yaml` split-pipeline convention are
  detected — a child pipeline at a conventionless path (`ci/build.yml`) is not, since no
  filename convention distinguishes it from any other YAML file
- Nested `include:` directives inside an included file are not recursively resolved
- `project:` includes carry no host segment in GitLab's own syntax — without
  `registries.gitlab_instance_host` configured, they (and any `$CI_SERVER_FQDN`-relative
  `component:` include) are parsed but not version-resolved, with an informational
  diagnostic naming the setting as the remedy
- A `workspace/didChangeConfiguration` that changes `registries.gitlab_instance_host` does
  not re-parse documents already open — the change applies on their next edit or reopen
  (tracked in [#592](https://github.com/bug-ops/deps-lsp/issues/592))
- At most 8 distinct literal `component:` hosts are resolved per document; further distinct
  hosts are logged and left unresolved (bounds per-`didOpen` connection fan-out)
- Package-name completion is unimplemented (`search()` always returns empty): no cheap
  GitLab search endpoint exists under the rate-limit budget
- GitLab's CI/CD Catalog component-name path split (`<fqdn>/<project-path>/<component-name>`)
  assumes the last path segment is the component name — GitLab's own documented shape, with
  no server-side confirmation available offline

## License

[MIT](../../LICENSE)

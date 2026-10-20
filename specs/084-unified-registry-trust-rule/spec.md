---
aliases:
  - Unified registry trust rule
  - Operator-owned registry sources
  - URL-alone registry trust
tags:
  - sdd
  - spec
  - security
  - cross-ecosystem
  - deps-core
created: 2026-10-19
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[082-interactive-registry-await-failure-memo/spec|082 Interactive registry await failure memo]]"
---

# Feature: One URL-alone registry trust rule across ecosystems

> [!info] Metadata
> **Branch**: `feat/1854-breaker-evidence-egress-provenance`
> **Priority**: P2
> **Category**: security / cross-ecosystem
> **Issue**: #1822 (shipped together with #1853, #1854, #1836)

## 1. Overview

### Problem Statement

Swift decides registry trust from the URL alone: a URL equal to one declared in the user's own `registries.json` is trusted whichever tier declared it in the current workspace. Cargo trusted by alias provenance (`$CARGO_HOME` and `CARGO_REGISTRIES_*` trusted, a repository file not). Go (`$GOENV` `GOPROXY`), npm (`~/.npmrc`) and NuGet (user-profile `NuGet.Config`) read operator-owned files too, yet treat every URL as workspace-declared: they enforce the workspace policy on the operator's own URL and route it through the guarded egress tier (no system proxy, RFC1918 refused under `public_only`). A corporate registry the operator configured is therefore unreachable behind a proxy or on a private address, and the same URL behaves differently per ecosystem.

### Rule

A registry URL is **Trusted** if and only if its canonical form equals a URL declared in an operator-owned file, whichever tier declared it in this workspace. Otherwise it is **WorkspaceDeclared**. The canonical form is the parsed URL after `${VAR}`/`%VAR%` expansion with the trailing `/` trimmed; equality is per URL, never per host.

An operator-owned file is one located through the user's home directory or an **absolute** operator environment path (`GOENV`, `XDG_CONFIG_HOME`, `APPDATA`). A relative path is never operator-owned. An empty variable is unset. Whether a relative value falls back to a default is per ecosystem: Go reads no file, NuGet tries its home-based defaults, Swift treats its user tier as unusable.

## 2. Requirements (EARS)

- **FR-001**: The system shall treat a registry URL as Trusted when its canonical form equals a URL declared in an operator-owned file of the same ecosystem.
- **FR-002**: When a URL is Trusted, the system shall skip the workspace registry policy at URL-validation time and at connect time, including `workspace_registries = "off"`, and shall fetch it over the Baseline egress tier with the system proxy.
- **FR-003**: When a URL is Trusted, the system shall still reject a host of a class that is never a registry (loopback, link-local, cloud metadata, unspecified, reserved), for the registry URL and for every resource URL a trusted feed's service index names, and shall still enforce the Baseline floor guard.
- **FR-004**: When a URL is not equal to an operator-declared URL, the system shall validate it under the workspace policy and fetch it over the Guarded egress tier, even if it shares a host with an operator-declared URL.
- **FR-005**: The operator URL set shall be built from the post-expansion canonical URLs of the operator-owned file, so an entry written with `${VAR}` equals its expanded form.
- **FR-006**: Where an operator path comes from an environment variable, the system shall accept it only through a closed set of variable names, and only when it is absolute; `GOENV=off` shall disable the Go file and shall not be read as a relative path, and an empty variable shall be treated as unset.
- **FR-007**: If the user home directory is not absolute, then the system shall report no home.
- **FR-008**: Cargo, Go, npm, NuGet and Swift shall apply FR-001 to FR-007 through one shared implementation in `deps-core`.
- **FR-009**: Cargo shall classify an index URL by FR-001 against the URLs declared in `$CARGO_HOME/config.toml` (`[registries]` and `[source]` sparse terminals) and in every `CARGO_REGISTRIES_*_INDEX` variable of the process environment, whichever file, alias or manifest field named the URL. The operator set does not depend on the manifest being parsed. A relative `CARGO_HOME` is not operator-owned.
- **FR-010**: Cargo shall decide a registry credential separately from egress, and bind it to a URL the operator declared: a token declared with a `$CARGO_HOME` registry or a `CARGO_REGISTRIES_*` variable is sent to that URL, whichever alias, `[source]` chain or manifest field names it, and to no other URL. Where two aliases give one URL different tokens, the alias that sorts first wins. The outcome shall not depend on registration order or on which manifest is parsed.

## 3. Decisions and residual risks

- **Accepted relaxation (S3)**: an operator-declared host that resolves to a private address becomes reachable under `public_only`. The operator wrote the URL; the rule makes that provenance impossible for a repository to plant.
- **`workspace_registries = "off"` (S2)**: it no longer blocks operator-owned sources or a repository URL equal to one of them. It continues to block every other workspace-declared URL.
- **Env trust boundary (M9)**: an absolute `GOENV` or `XDG_CONFIG_HOME` exported by repository-scoped environment tooling (direnv `.envrc`, mise, per-project shell capture in an editor) counts as operator-owned. That is the environment trust boundary of #1459, gated by the tool's own trust prompt; no code change.
- **Redirects (#1856)**: a request that can carry a credential is origin-confined. An anonymous Trusted npm or Go metadata fetch *may* leave its origin, because operator proxies (Athens in redirect mode, Artifactory redirecting to object storage) do so on purpose; the never-a-registry floor and the https-downgrade stop still apply on every hop, and a hop stopped by a credential-bearing or origin-confined request is logged at WARN once per origin pair with both origins redacted (an anonymous fetch stops silently). Cargo's anonymous Trusted index fetches follow the same permission. A credential embedded in a request URL (a query or path token) is not a header and is not confined, so the shared client sends no `Referer`. NuGet and Swift keep their anonymous Trusted fetches origin-confined by choice. Live checks found no cross-origin redirect on the metadata endpoints of goproxy.cn, goproxy.io, proxy.golang.org or registry.npmmirror.com.
- **Behavior change (#1855)**: the never-a-registry floor now applies to a `$CARGO_HOME` registry, so one on a loopback or link-local host is rejected, as for the other ecosystems.

## 4. Acceptance

- Same URL in the user file and the project file is Trusted for npm, NuGet and Swift; a project-only URL is WorkspaceDeclared.
- An interpolated user-tier npm URL is Trusted.
- `workspace_registries = "off"` with an operator URL is reachable; with a project-only URL it is blocked.
- Same host, different path from an operator URL stays WorkspaceDeclared and is blocked on RFC1918.
- `GOENV=off`, a relative `GOENV`, a relative `XDG_CONFIG_HOME` and a relative home each yield no operator tier.
- A cross-ecosystem consistency test asserts the egress tier for Cargo, Go, npm, NuGet and Swift under the rule.
- A Cargo credential is attached only to an operator-declared URL it is bound to, and identically on every run: a workspace alias, a literal `registry-index` or a replace-with chain naming that URL gets it, and any other URL never does.
- A cross-origin redirect hop carries no `Referer`.

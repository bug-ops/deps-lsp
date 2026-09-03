---
aliases:
  - Docker Base Image Ecosystem
  - Dockerfile FROM Tag/Digest Freshness
tags:
  - sdd
  - spec
  - research
  - ecosystem/docker
  - new-ecosystem
  - priority/p4
created: 2026-09-04
status: draft
related:
  - "[[MOC-specs]]"
  - "[[014-github-actions-ecosystem/spec]]"
  - "[[030-gitlab-ci-ecosystem/spec]]"
  - "[[031-github-actions-sha-pin-diagnostic/spec]]"
---

# Feature: New ecosystem — Dockerfile `FROM` base-image tag/digest freshness

> [!info] Metadata
> **Author**: continuous-improvement research cycle ci-035, task "Research: Dockerfile dependency support
> feasibility" (2026-09-04)
> **Branch**: tracked by issue #557 (research/spec-only — no implementation branch yet)
> **Type**: research / new ecosystem

## 1. Overview

### Problem Statement

`Dockerfile` has no single "dependency manifest" the way `Cargo.toml` or `package.json` do. A prior research
pass had to first decide *what* "Dockerfile dependencies" would even mean before any implementation could be
scoped. Four distinct sub-scopes exist, with very different feasibility:

1. **`FROM <image>[:<tag>][@sha256:...]` base-image references** — the closest analogue to a normal
   dependency: a name + a version-ish tag, resolvable against a registry (Docker Hub / any OCI-compliant
   registry) for newer tags, EOL/deprecated base images, and digest-pinning status. Structurally similar to
   the [[014-github-actions-ecosystem/spec|GitHub Actions `uses:` ecosystem]] (#208) and its
   [[031-github-actions-sha-pin-diagnostic/spec|mutable-ref-pin diagnostic]] (#473): a name@ref pin, checked
   against a tags API, with a parallel "prefer the immutable form" hardening recommendation (digest over
   tag, same shape as SHA-pin over branch/tag).
2. **Multi-stage build stage references** (`FROM builder AS stage`, later `FROM stage`/`COPY --from=stage`)
   — purely internal to the file; not an external dependency, must be excluded from resolution (a stage name
   is not an image name).
3. **Package-manager invocations inside `RUN` lines** (`apt-get install foo=1.2.3`, `apk add`,
   `pip install foo==1.2.3`, `npm install foo@1.2.3`, `pip3 install -r requirements.txt`, heredocs,
   multi-line `\`-continuations) — a fundamentally different, much fuzzier parsing problem: shell-command
   parsing, not manifest parsing, and for several package managers it overlaps ecosystems deps-lsp already
   supports natively via their real manifest files (PyPI, npm). Distinct effort class from (1).
4. **`COPY --from=<image>` references to external (non-stage) images** — structurally identical to `FROM`
   for resolution purposes (a name + optional tag/digest), but rarer in practice and a straightforward
   extension of (1) rather than new complexity once (1) exists.

This spec scopes a v1 candidate around **(1) only** — `FROM` base-image tag/digest freshness — with (4) as a
natural, low-cost follow-on, and (2)/(3) explicitly out of scope (see below).

### Demand Signal

`gh issue list --search "docker"` / `--search "dockerfile"` (2026-09-04, all states) returns no issue about
Dockerfile dependency support. The one hit for "docker" — issue #474 (closed) — is about `deps-github-actions`
mishandling `uses: docker://...` step references (a *GitHub Actions* pin shape, not this feature) and is
unrelated. There is currently **no user-requested demand** for this feature; it originates from a
research-cycle competitive/architecture scan, the same origin as #208 (GitHub Actions) and #466 (GitLab CI).

Neither root `README.md` nor `docs/ECOSYSTEM_GUIDE.md` currently mention Docker/Dockerfile in the supported
ecosystem list (13 ecosystems today: Cargo, npm, PyPI, Go, Bundler, Dart, Maven, Composer, Gradle, Swift,
NuGet, Deno, GitHub Actions).

### Goal

deps-lsp detects `Dockerfile`/`*.dockerfile`/`Containerfile` files, parses `FROM` instructions (all stages,
skipping stage-name references such as `FROM builder AS x` / bare `FROM stage`), resolves the referenced
image's available tags and, where the pin is a tag, whether that tag currently maps to a manifest digest
different from any cached resolution (freshness), via a Docker-Registry-HTTP-API-V2 (OCI Distribution Spec)
client, and surfaces hover (current tag/digest, latest tag, pin status), an outdated-tag diagnostic, and a
mutable-tag-pin hardening diagnostic (recommend `@sha256:...` pinning) — consistent in shape with the
existing GitHub Actions mutable-ref-pin diagnostic (#473) and formatter/registry patterns used by
`deps-github-actions`/`deps-swift`.

### Out of Scope

- **Package-manager invocations inside `RUN` lines** (`apt-get`, `apk`, `pip install`, `npm install`, etc.)
  — a distinct shell-parsing problem overlapping ecosystems deps-lsp already supports through their native
  manifest files; a future spec of its own if ever pursued, not part of this candidate.
- **Multi-stage internal stage references** (`FROM builder AS x`, `FROM x`, `COPY --from=x`) — not external
  dependencies; must be recognized and skipped, not resolved.
- **Docker Compose (`docker-compose.yml`) `image:` fields**, and other manifests referencing Docker image
  tags (e.g. GitLab CI's `image:`/`services:`, out of scope per
  [[030-gitlab-ci-ecosystem/spec|the GitLab CI spec]]) — same underlying registry-datasource concept as
  `FROM`, but a different manifest format/detection path per caller; deferred to a follow-up spec once this
  one ships and proves out the base registry-resolution logic, so no ecosystem needs to re-implement its own
  Docker-image resolution from scratch.
- **Private registry authentication beyond Docker Hub's anonymous-token flow** — self-hosted / authenticated
  registries (GHCR with a PAT, private ECR, etc.) are a v2 concern; v1 targets Docker Hub and any registry
  reachable via the standard anonymous `GET /v2/<name>/tags/list` + `www-authenticate` bearer-token flow
  used by public images.
- **Vulnerability/CVE scanning of image contents** — that is Trivy/Docker Scout/Grype's job, not a
  dependency-freshness signal; out of scope entirely, not just deferred.
- **EOL/deprecated base-image advisory data** (e.g. flagging `python:3.8` as EOL) — no existing deps-lsp
  registry integration carries this kind of curated lifecycle data; worth a follow-up research item, not
  this spec.
- **`COPY --from=<image>` external-image references** — structurally reuses (1)'s resolution once it exists,
  but is deferred to keep v1's parser surface to one instruction (`FROM`) until that lands and proves out.

## 2. Prior Art

- **Renovate** — `docker` datasource covers `FROM` tag freshness and offers a `docker:pinDigests` preset
  that rewrites `FROM node:14` to `FROM node:14@sha256:<digest>` while keeping the tag for readability. This
  is the closest existing template for both the freshness check and the pin-hardening recommendation this
  spec proposes.
- **Dependabot** — has native Docker ecosystem support (`package-ecosystem: "docker"`) for `FROM` tag
  updates in Dockerfiles, unlike its total lack of native GitHub Actions `uses:`-adjacent competition that
  made #208 attractive; this weakens (but does not eliminate) the "no existing tool solves this" argument
  compared to #208's clean-field start.
- **Trivy / Docker Scout** — vulnerability and SBOM scanners for image *contents*; do not address tag/digest
  freshness as an editor-time signal, orthogonal to this spec.
- **hadolint** — Dockerfile best-practice linter (`FROM` pinning conventions, `apt-get` cache-cleanup
  hygiene, etc.); flags the *absence* of a tag/digest pin as a style issue but does not fetch registry data
  or report *how outdated* a pin is — complementary to, not competing with, this spec.

Net: unlike #208 (a genuinely unserved gap when spec'd), Docker `FROM` freshness already has two mature,
widely-adopted competitors (Renovate, Dependabot) with native support. The differentiator deps-lsp would
offer is in-editor, LSP-native surfacing (hover/inlay-hint/code-action) rather than PR-bot surfacing —
matching this project's stated angle for every other ecosystem, but a materially weaker "gap in the market"
case than #208 had.

## 3. Feasibility Assessment

### Architecture fit

Mirrors the existing `deps-github-actions` pattern (a non-package-manager "manifest" with a registry API
resolving `name@ref` pins): `Ecosystem` trait impl, `Registry` trait impl, `ParseResult`/`Dependency`
impls, `EcosystemFormatter` for hover/inlay-hint rendering, wired into `EcosystemRegistry` by filename
(`Dockerfile`, `Containerfile`) and pattern (`*.dockerfile`). No changes to `deps-core`'s trait surface are
anticipated beyond what #208 already required.

### Parsing

`Dockerfile` syntax is line-oriented but has continuations (`\` line-splices), comments, and ARG
substitution inside image references (`FROM ${BASE_IMAGE}:${TAG}`) — the last of which cannot be resolved
without evaluating build args, and should be treated as unresolvable/skipped rather than guessed. No
existing workspace dependency parses Dockerfile syntax; this would be the first hand-rolled instruction
parser (contrast with `yaml-rust2` reuse across `deps-dart`/`deps-github-actions`/`deps-gitlab-ci`). Line/
continuation handling and quoting rules are simpler than YAML but still a new, from-scratch grammar surface
distinct from every other ecosystem in the workspace, which is a maintenance cost.

### Registry client

No workspace dependency currently speaks the Docker Registry HTTP API V2 / OCI Distribution Spec. Two
maintained third-party Rust crates cover it — `oci-client` (github.com/oras-project/rust-oci-client, part of
the ORAS/CNCF-adjacent ecosystem, actively maintained) and `oci-registry-client`
(github.com/ecarrara/oci-registry-client) — either of which would need vetting (license, maintenance
cadence, dependency-tree weight) against the project's "hand-roll HTTP calls like crates.io/npm" pattern
used everywhere else in the workspace. Alternatively, given the actual surface needed is narrow
(`GET /v2/<name>/tags/list` for the tag list, `HEAD`/`GET /v2/<name>/manifests/<tag>` with the
`Accept: application/vnd.oci.image.index.v1+json`/`application/vnd.docker.distribution.manifest.v2+json`
header for digest resolution, plus Docker Hub's anonymous bearer-token dance via
`auth.docker.com/token?service=registry.docker.io&scope=repository:<name>:pull`), a hand-rolled client
consistent with the rest of the workspace is plausible and would avoid a new dependency — this is an
implementation-time decision, not a blocker.

### Version comparison

Base-image tags are frequently **not semver** (`3.12-slim`, `alpine3.19`, `lts`, `jammy`, `20.04`) — closer
to the "non-semver tag" problem `deps-github-actions` already solved (`is_tag_shaped`/tag-vs-branch
classification, and #552's non-semver/literal-tag classification fix) than to `semver`/`node-semver`-style
range matching. "Outdated" for this ecosystem likely means "a newer digest exists behind the same tag" or
"a numerically-newer tag variant exists" rather than a strict semver comparison — this needs its own
classification logic, not reuse of an existing version-matcher crate.

### Complexity vs #208/#466 baseline

Higher floor than #208 (single fixed host `api.github.com`, existing YAML parser) and comparable to #466
(GitLab CI, still unshipped, P4): new instruction-syntax parser, new registry protocol/client, non-semver
tag comparison, and (deferred to v2) multi-registry/auth handling. Materially larger than either "add one
more manifest format to an existing pattern" ecosystem (e.g. #027 NuGet, #033 PyPI private-index) has been.

## 4. Recommendation

**Go, narrowly scoped, at P4 ("nice to have").** The architecture fits the existing `deps-github-actions`
precedent well, and the mutable-tag-vs-digest-pin diagnostic is a natural extension of the already-shipped
mutable-ref-pin pattern (#473) — reusing that design, not inventing a new one. However:

- Demand signal is currently zero (no issues, no user request) — this is a competitive-parity /
  architecture-fit finding, not a responsive fix.
- Renovate and Dependabot already serve this need well outside the editor; deps-lsp's differentiator is
  purely "in-editor, same UX as every other ecosystem," which is real but narrower than #208's original
  "nothing else solves this" case.
- New parser grammar + new registry protocol + non-semver comparison logic makes this a larger, riskier
  build than most P3/P4 backlog items currently in `specs/`.

Recommended v1 scope if implemented: **`FROM` tag/digest freshness only**, Docker Hub + anonymous-bearer-token
OCI registries only, no `RUN`-line package parsing, no Compose support, no private-registry auth. This spec
stops at `specify`; do not proceed to `/sdd plan`/`/sdd tasks` until either user demand appears or the
project actively wants to widen ecosystem coverage into non-package-manager manifests beyond GitHub Actions/
GitLab CI.

## 5. User Stories

### US-001: See outdated/mutable base-image pins in-editor

AS A developer maintaining a `Dockerfile`
I WANT to see, at a glance, whether a `FROM` base image's tag is outdated and whether it is pinned to a
mutable tag rather than an immutable digest
SO THAT I can decide whether to update the tag or harden the pin, without leaving the editor to check the
registry.

**Acceptance criteria:**
```
GIVEN a Dockerfile with one or more `FROM <image>[:<tag>][@sha256:...]` instructions referencing external
      images (not build stages)
WHEN the editor requests hover over a FROM instruction
THEN the server SHALL show:
     - The resolved tag and, if present, digest
     - Whether a newer digest exists behind the same tag (freshness)
     - Whether the pin is mutable (tag-only) vs immutable (digest-pinned)
     - A code action to add/update the digest pin, when resolvable
```

### US-002: Multi-stage builds are not falsely flagged

AS A developer using multi-stage Dockerfiles (`FROM golang:1.23 AS builder`, later `FROM builder`)
I WANT internal stage references left alone
SO THAT I don't get nonsensical "unknown image" diagnostics on my own build-stage names.

**Acceptance criteria:**
```
GIVEN a Dockerfile with a `FROM <image> AS <stage>` instruction and a later `FROM <stage>` instruction
      referencing that stage name
WHEN the server parses the file
THEN the later `FROM <stage>` SHALL be recognized as an internal stage reference and excluded from
     registry resolution and diagnostics entirely
```

### US-003: Consistent behavior with other ecosystems

AS A developer working across multiple manifest types in one repository
I WANT Dockerfile hover/diagnostics/inlay-hint/code-action behavior to match the conventions of every other
supported ecosystem
SO THAT I don't have to learn ecosystem-specific quirks, per the project's cross-ecosystem-consistency rule.

**Acceptance criteria:**
```
GIVEN equivalent "outdated pin" scenarios in a Dockerfile and in a GitHub Actions workflow
WHEN the server processes both
THEN diagnostic severity mapping, hover section structure, and code-action wording SHALL follow the same
     conventions (adapted only where the underlying concept genuinely differs, e.g. digest vs SHA)
```

## 6. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect `Dockerfile`, `Containerfile`, and `*.dockerfile` files by filename/pattern and register them as manifest documents | must |
| FR-002 | THE SYSTEM SHALL parse `FROM <image>[:<tag>][@sha256:<digest>] [AS <stage>]` instructions across all build stages, handling line continuations (`\`) and comments | must |
| FR-003 | THE SYSTEM SHALL recognize `FROM <stage>` references to a prior `AS <stage>` name (case-insensitive, per Dockerfile semantics) and exclude them from registry resolution and diagnostics | must |
| FR-004 | THE SYSTEM SHALL recognize `FROM` values containing unresolved `${ARG}`/`$ARG` build-arg substitution as unresolvable and skip them gracefully, without a false diagnostic | must |
| FR-005 | THE SYSTEM SHALL resolve an image reference's registry host (defaulting to Docker Hub / `registry-1.docker.io` when no host is present, per standard Docker image-reference resolution rules) and repository path (applying the `library/` prefix for official unqualified images, e.g. `alpine` → `library/alpine`) | must |
| FR-006 | THE SYSTEM SHALL fetch the tag list for a resolved image via the Docker Registry HTTP API V2 `GET /v2/<name>/tags/list` endpoint, using the anonymous bearer-token flow (`www-authenticate` challenge → token exchange) for public images | must |
| FR-007 | WHEN a `FROM` pin specifies a tag (not a digest) THE SYSTEM SHALL resolve the tag's current manifest digest via `GET/HEAD /v2/<name>/manifests/<tag>` and cache it, to detect when the same tag's digest has changed since last observed | must |
| FR-008 | THE SYSTEM SHALL produce a diagnostic when a `FROM` tag pin is mutable (no `@sha256:` digest present), recommending digest pinning — mirroring the shape (not necessarily the exact wording) of the existing GitHub Actions mutable-ref-pin diagnostic (#473) | must |
| FR-009 | THE SYSTEM SHALL produce hover content for a `FROM` instruction showing the resolved tag, resolved/cached digest, and pin-mutability status | must |
| FR-010 | THE SYSTEM SHALL expose a code action to add or refresh a `@sha256:<digest>` pin on a `FROM` instruction, applied as a `WorkspaceEdit`, when the digest is resolvable | should |
| FR-011 | THE SYSTEM SHALL NOT parse or resolve `RUN`-line package-manager invocations (`apt-get`, `pip install`, etc.) — explicitly out of scope for this ecosystem | must |
| FR-012 | THE SYSTEM SHALL NOT parse `COPY --from=<image>` external-image references in v1 — explicitly deferred | must |
| FR-013 | WHEN the registry returns 401/403/404, or the host is unreachable THE SYSTEM SHALL degrade gracefully — cached data (if any) is served, otherwise hover/diagnostics show an informational "could not resolve" state, never a false "outdated" positive | must |
| FR-014 | THE SYSTEM SHALL produce equivalent hover/diagnostic/inlay-hint/code-action behavior across all Dockerfile instances, consistent with the cross-ecosystem-consistency rule | must |

## 7. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Tag-list and digest lookups SHALL be cached (TTL + conditional requests where the registry API supports them) so repeated hovers on an unchanged Dockerfile do not re-hit the registry |
| NFR-002 | Rate limiting | Docker Hub enforces anonymous pull-rate limits (historically 100 pulls/6h per anonymous IP for manifest/tag operations); the system SHALL minimize registry calls via caching and SHALL degrade gracefully (cached-data fallback), not retry aggressively, when rate-limited |
| NFR-003 | Reliability | Digest/tag resolution failures for one `FROM` instruction SHALL NOT block parsing or resolution of other instructions in the same file |
| NFR-004 | Consistency | Hover format, diagnostic wording conventions, and code-action UX SHALL follow the same structural conventions as other ecosystems, adapted only where digest-vs-SHA semantics genuinely differ |
| NFR-005 | No new grammar dependency creep | The Dockerfile instruction parser SHALL be hand-rolled (line/continuation/comment handling), consistent with the project's preference for minimal new parsing dependencies unless an existing, already-used crate can be reused — none currently can |
| NFR-006 | Registry client dependency | Whether to hand-roll the OCI Distribution Spec HTTP calls (consistent with the project's crates.io/npm/PyPI pattern) or adopt a third-party crate (`oci-client`) is an implementation-time decision requiring explicit sign-off — see Agent Boundaries |

## 8. Data Model

No new persistent entities beyond the existing `Dependency`/`ParseResult`/`DocumentState` machinery.

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| Base-image reference (derived) | A `FROM` instruction referencing an external image | registry host, repository path, tag (optional), digest (optional), is-stage-reference (bool) |
| Stage reference (derived, excluded) | A `FROM`/`COPY --from=` reference to a prior `AS <stage>` name | stage name only — never resolved against a registry |
| Image tag list (cached) | Response from `GET /v2/<name>/tags/list` | tag names, per-(host,repo) cache key |
| Manifest digest (cached) | Digest resolved for a given (host, repo, tag) | sha256 digest, resolution timestamp |

## 9. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `FROM scratch` | Recognized as the special empty base image; no registry resolution, no diagnostic |
| `FROM <stage-name>` referencing an earlier `AS <stage-name>` | Excluded from resolution entirely (FR-003) |
| `FROM ${BASE_IMAGE}` / `FROM $BASE:${TAG}` (unresolved build args) | Skipped gracefully, no false diagnostic (FR-004) |
| `FROM image` (no tag, defaults to `:latest`) | Treated as maximally mutable; still eligible for the mutable-pin diagnostic |
| `FROM image@sha256:...` (already digest-pinned, no tag) | No mutable-pin diagnostic; hover shows the pinned digest and, if resolvable, which tag(s) currently point at it |
| Multi-stage Dockerfile with several external `FROM` images | Each resolved independently; diagnostics/hover per-instruction, consistent with other ecosystems' per-line diagnostics |
| Image reference targets a private registry requiring auth this ecosystem doesn't support (v1) | Informational "could not resolve" state, not an error/false-positive diagnostic |
| Docker Hub anonymous rate limit exhausted | Cached data served if available; otherwise informational state; no aggressive retry |
| Dockerfile with zero `FROM` instructions, or a syntactically invalid file | No diagnostics; parse errors logged and handled gracefully, consistent with other ecosystems |

## 10. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Manifest detection | `Dockerfile`/`Containerfile`/`*.dockerfile` correctly routed to this ecosystem |
| SC-002 | Stage-reference exclusion | 100% of internal stage `FROM`/`COPY --from=` references excluded from registry resolution in test fixtures |
| SC-003 | Hover coverage | Hover shows tag/digest/mutability status for all resolvable external `FROM` references |
| SC-004 | Mutable-pin diagnostic accuracy | Diagnostic fires on every tag-only pin and never on a digest-pinned reference, verified against fixture Dockerfiles |
| SC-005 | Graceful degradation | Unreachable/rate-limited/private registries never produce a false "outdated" diagnostic |
| SC-006 | Cross-ecosystem consistency | Hover/diagnostic/code-action structure verified consistent with `deps-github-actions`'s equivalent mutable-ref-pin feature, documented in `.local/testing/coverage.md` |

## 11. Agent Boundaries

### Always (without asking)
- Follow the existing `Ecosystem`/`Registry`/`ParseResult`/`Dependency`/`EcosystemFormatter` trait pattern
  established by `deps-github-actions`.
- Exclude stage-name `FROM`/`COPY --from=` references from any registry resolution (FR-003) — this is not
  optional given how easily it produces false positives otherwise.
- Run the full check suite before considering any implementation complete.

### Ask First
- Whether to hand-roll the OCI Distribution Spec HTTP calls or adopt `oci-client`/`oci-registry-client` as a
  new dependency (NFR-006) — a real trade-off between "consistent with the rest of the workspace's
  hand-rolled registry clients" and "reuse a maintained, spec-compliant implementation."
- Designing the non-semver tag-freshness classification logic (what counts as "a newer tag exists" for
  `3.12-slim` vs `3.13-slim` vs `latest`) — this is new comparison logic, not a reuse of `semver`/
  `node-semver`, and deserves explicit design review before implementation.
- Any registry-auth abstraction beyond Docker Hub's anonymous bearer-token flow (private registries, GHCR
  PATs) — explicitly deferred to a v2 decision.

### Never
- Parse or resolve `RUN`-line package-manager invocations under this ecosystem (FR-011) — a separate concern
  if ever pursued, not part of this spec.
- Silently guess a value for an unresolved `${ARG}` build-arg substitution in a `FROM` line.
- Treat an unreachable/rate-limited registry response as grounds for an "outdated" diagnostic — silence
  (informational state) is always preferred over a false positive here.

## 12. Open Questions

- [NEEDS CLARIFICATION: Is there any actual user demand for this feature, or should it remain parked at
  `specify` phase indefinitely given zero current issue/discussion signal? Recommend revisiting only if a
  user files a request or a future competitive scan shows a widened gap.]
- [NEEDS CLARIFICATION: Hand-roll the OCI Distribution Spec client vs. adopt `oci-client` — needs an
  explicit dependency-weight/maintenance-risk assessment before `/sdd plan`.]
- [NEEDS CLARIFICATION: What exact "outdated" semantics apply to non-semver tags (e.g. `3.12-slim` vs newer
  `3.13-slim`, or same-tag digest drift like `latest`)? Needs its own design pass, likely informed by how
  Renovate's `docker` datasource currently classifies tag freshness.]
- [NEEDS CLARIFICATION: Should `Containerfile` (Podman's naming convention) really share one ecosystem impl
  with `Dockerfile`, or does the project want a narrower v1 scoped to `Dockerfile` only?]
- [NEEDS CLARIFICATION: No project constitution exists at `specs/constitution.md` yet — cannot validate this
  spec against project-wide architectural principles beyond precedent-matching against #208/#466.]
- [NEEDS CLARIFICATION: Given P4 priority and no demand signal, should the filed tracking issue block on
  #466 (GitLab CI, also P4, also unimplemented) landing first to prove out the "non-package-manager,
  non-GitHub-Actions manifest" pattern a second time before a third such ecosystem is attempted?]

## 13. See Also

- #208 — GitHub Actions `uses:` pins, spec [[014-github-actions-ecosystem/spec]] — closest architectural
  precedent (name@ref pin resolved via a tags API).
- #473 — GitHub Actions mutable-ref-pin diagnostic, spec [[031-github-actions-sha-pin-diagnostic/spec]] —
  direct template for this spec's "recommend the immutable form" diagnostic (SHA pin there, digest pin
  here).
- #466 — GitLab CI `include:` ecosystem candidate, spec [[030-gitlab-ci-ecosystem/spec]] — sibling
  unimplemented P4 new-ecosystem candidate; that spec explicitly deferred `image:`/`services:` Docker tags
  to "a future Docker image tags ecosystem candidate" — this spec is that candidate.
- `crates/deps-github-actions/src/parser.rs` — event-driven parsing precedent, and the reasoning for
  treating certain reference shapes (there: reusable-workflow calls; here: stage references) as
  non-resolvable rather than guessed.
- `crates/deps-github-actions/src/registry.rs`, `crates/deps-swift/src/registry.rs` — closest existing
  precedents for a hosted-tags-API registry client with token-based rate-limit handling.
- [Renovate `docker` datasource docs](https://docs.renovatebot.com/docker/)
- [Renovate `docker:pinDigests` preset discussion](https://github.com/renovatebot/renovate/discussions/35428)
- [Docker Registry HTTP API V2 / OCI Distribution Spec reference](https://docs.docker.com/reference/api/registry/latest/)
- [`oci-client` (oras-project/rust-oci-client)](https://github.com/oras-project/rust-oci-client)
- [`oci-registry-client` (ecarrara/oci-registry-client)](https://github.com/ecarrara/oci-registry-client)
- [hadolint — Dockerfile linter](https://github.com/hadolint/hadolint)
- [[MOC-specs]] — all specifications

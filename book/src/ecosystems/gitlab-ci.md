# GitLab CI/CD

## Basics

Like GitHub Actions, GitLab CI/CD is a CI/CD supply-chain pinning ecosystem, not a language
package manager — `deps-lsp` tracks the `include:` directive, which pulls in job definitions
from another project or a published CI/CD Catalog component. Manifests are `.gitlab-ci.yml` at
the repository root, or any `.yml`/`.yaml` file under `.gitlab/ci/` (directory-pattern match,
same mechanism GitHub Actions uses for `.github/workflows/`).

Two pinnable `include:` forms are recognized:

```yaml
include:
  - project: 'my-group/my-project'
    ref: v1.2.0
    file: '/templates/build.yml'
  - component: gitlab.com/my-group/my-component/my-module@1.0
```

A `project:`/`ref:` include resolves against that project's git tags (GitLab's
`GET /projects/:id/repository/tags` API); a `component:` include resolves against the
project's **published releases** (`GET /projects/:id/releases`) — a CI/CD Catalog component
version is a release, not a bare tag. `.gitlab-ci.yml` also commonly uses YAML anchors/aliases
to reuse job templates, which `deps-gitlab-ci` resolves faithfully (see below) so a pinned
version hidden behind an alias is still tracked correctly. Like GitHub Actions, there is no
package registry involved — only the mutable-ref-vs-SHA distinction described in [CI/CD
Pinning](../cross-ecosystem/ci-pinning.md).

## YAML Anchor/Alias Resolution

`.gitlab-ci.yml` supports YAML anchors (`&name`) and aliases (`*name`) for reuse — GitLab's
own docs recommend anchor-based templates as the standard way to reduce duplication across
jobs. Within the `include:` subtree, both **scalar** anchors (a `ref:`, `project:`, or
`component:` value aliased elsewhere) and **mapping-shaped** anchors (a whole `include:`
entry reused via `- *tpl`, `include: *tpl`, `- <<: *tpl`, or `- <<: [*a, *b]`) resolve
correctly, with hover/diagnostics/inlay hints positioned at the **alias token** (not the
anchor's definition site).

**Merge-key (`<<:`) precedence matches what GitLab's own YAML loader (Ruby Psych) actually
resolves**, not the abstract YAML 1.1 merge-key spec's "explicit keys always win" reading —
the two disagree in several cases: `<<:` is applied *positionally*, like any other key, so an
own key written **before** `<<:` loses to the merged value, while one written **after** wins;
`<<: [*a, *b]` is first-wins when both templates define the same key; two separate `<<:` keys
in one mapping are last-wins (a different result from the sequence form); and a template
reached through a chain of merges (`.c: &c {<<: *b}` where `.b` itself merges `*a`) resolves
transitively with the same rules at each level, no special-casing.

**SHA-pin quickfix and version completion are withheld at the alias site itself**, scoped to
whichever field actually backs `version_range` (`ref:` for a `project:` include, `component:`'s
own field) — resolving an alias (scalar or container) produces a value with no editable
literal span at that position, since rewriting it would need to edit the anchor definition
instead. This is tracked per-field, not per-entry: a merged/aliased `project:` next to a
literal `ref:` is unaffected — only the field that is itself alias-derived loses its
quickfix/completion.

**Two documented, deliberate divergences from Psych** (both accepted rather than fixed — see
the linked spec for the full rationale):
- A doubly-nested explicit `null` inside a merge chain (e.g. `- {ref: v9, <<: *b}` where `*b`
  is `{<<: *a, ref: ~}`) resolves to the entry's earlier literal value instead of Psych's
  `nil`, since this crate's field representation cannot distinguish "key absent" from "key
  present but null" the way Ruby's `Hash` can.
- A **scalar**-anchor alias resolved *through* a merge (e.g. `ref: *pin` where `*pin`'s own
  anchor text is null-like) is not re-checked for null-ness the way a directly-typed null
  scalar is, so it is captured as literal text rather than treated as absent.

**Remaining known limitation.** `include: *incs` — aliasing a whole **sequence** of N
entries from one alias token — is a structural won't-fix (#917): one alias token cannot back
N distinct entries' `name_range`/`version_range`, so this shape is deliberately never
detected (0 records, matching today's silent-drop behavior rather than a misleading partial
one).

## Self-Hosted Instances

`.gitlab-ci.yml`'s `include:` directive supports two version-pinnable forms:

- `include: - project: org/proj` + `ref: <tag|branch|sha>` — a plain git ref, resolved
  against the GitLab repository-tags API (`GET /projects/:id/repository/tags`).
- `include: - component: host/org/proj/name@<version>` — a CI/CD Catalog component pin,
  resolved against the project's **published releases**
  (`GET /projects/:id/releases`) — a component version *is* a Release; a tag with no
  release is never a resolvable component version.

**Component pin priority.** A `component:` pin is resolved in GitLab's own documented
order: commit SHA (exact) > exact release name > branch (honest-unknown — GitLab CI
never fetches `/repository/branches` for this, since it would double the request cost to
distinguish two cases that render identically) > `~latest` (highest published
non-prerelease release) > partial semver (`1.2`, `1`, via `semver::VersionReq` range
matching — `~1.2` matches `>=1.2.0, <1.3.0`).

**SHA pins.** A full 40-character SHA pin is classified against the route's tag index once
its tags (or releases) are loaded, the same way as in GitHub Actions: a SHA on the latest
release's commit is up to date; a SHA at an older tag, or that no tag points at, is reported
outdated and update-all re-pins it to the latest release's full SHA (never to a bare tag).
Before the index is populated the pin stays unresolved. This includes a pin on a non-release
commit newer than the latest release, which is reported outdated (effectively a downgrade).

### SHA-pin trailing comments (issue #1743)

A literal SHA `ref:` (or component `@<sha>`) may carry a trailing tag comment, as in GitHub
Actions:

```yaml
include:
  - project: 'my-group/my-project'
    ref: 44790937c6a1e4f0b1b1f1a0d0f6c2e3f4a5b6c7 # v1.117.0
    file: '/templates/build.yml'
```

- Update-all and the update quickfix rewrite the SHA and the comment together
  (`<new sha> # v1.120.0`). A plain or quoted pin without a comment gains one; quotes are kept. A
  comment is never deleted when the tag index has no answer.
- A comment naming a tag that is not the pinned commit's tag raises `sha-comment-mismatch`
  (severity `diagnostics.sha_comment_mismatch_severity`) and a hover warning. Nothing is reported
  while the tag index is cold, or while a truncated tag list lacks the SHA; a SHA the truncated
  list lacks never reads as up to date from its comment, whatever the comment's shape (unresolved
  instead). The exception is a comment naming a full version (`# v1.117.0`) that the truncated
  list maps to another commit: that comment is provably wrong, so it is not trusted, the status
  is unresolved and the mismatch is reported.
- A `project:` tag `ref:` that is a full release no tag of the complete Tags list matches
  (`ref: 1.117.0` beside tag `v1.117.0`) is unresolved instead of up to date and raises
  `unknown-ref` (severity `diagnostics.unknown_ref_severity`). A partial or suffixed ref
  (`v1`, `v1.x`, `v3-node20`) may be a branch, so it keeps the ahead-of-latest rule and is never
  reported; a `component:` include is never reported either, since a version without a release is
  not a missing tag. An exact tag `ref:` that a truncated Tags list does not reach is unresolved
  as well, never up to date. A partial `project:` ref (`1.2`) is read as a branch, so the
  truncated-list rule for floating partial pins described there does not apply. See [GitHub Actions](github-actions.md#unpublished-refs-and-the-unknown-ref-diagnostic-issue-1766)
  for the shape rules. The `Change ref to published tag <tag>` quickfix rewrites the `ref:` to
  the single published spelling that matches (issue #1781).
- A tags fetch that first populates or changes a project's tag index rescans every other open
  `.gitlab-ci.yml` that uses it, as for GitHub Actions (issue #1765).
- The `Correct version comment to <tag>` quickfix rewrites only the comment's tag to the tag the
  pinned commit carries. It is offered only when the comment names another tag of that commit,
  not for an unknown SHA, a confirmed comment or a pin without one.
- A non-version update target (a release named `stable`) writes no `# tag`; trailing words in the
  old comment are kept.
- Version completion is withheld inside the comment.
- A comment on an alias site (`ref: *pin # v1.0.0`) is never read: the comment can go stale after
  the anchor is updated, with no mismatch diagnostic and no rewrite.
- The "Pin to commit SHA" quickfix, the bulk "Pin All to SHA" lens and the `~latest`/partial
  `component:` pin quickfix write `<sha> # <tag>` for a plain, last-on-line literal ref
  (`ref: v1.0.0`, `component: .../comp@1.0.0`). A quoted ref (`ref: "v1.0.0"`), a flow-style
  entry (`{project: org/proj, ref: v1.0.0, file: ci.yml}`) and a ref with more content after it
  get the bare SHA, since a comment cannot follow them; neighbouring keys are kept. An aliased
  ref is not edited at all.

A SHA pin tagged only by a floating tag below the latest release (`v1.1` while the latest is
`v1.1.0` on another commit) is reported outdated. SHA pins and tag pins are compared by the same
tag order, so a pre-release above the latest release (`v2.0.0-rc1` against latest `1.9.0`) is up
to date either way. As in GitHub Actions, a non-release commit newer than the latest release that
carries only a floating tag is reported outdated (tracked in #1725).

A `project:` tag pin resolves through the project's Tags list exactly like a GitHub Actions tag
pin (an exact release, a floating partial version, or unresolved), so hover and sibling-tag checks
see the same version in both ecosystems. A `component:` version stays unresolved here.

An exact `project:` tag pin that is ahead of the latest tag is reported up to date, unless the
loaded tag list is complete and has no such tag (`ref: v40.0.0`, a typo or a deleted tag): that
pin is unresolved, never outdated, so no downgrade is offered. A branch named like a version
reads the same way. This applies to `project:` includes only: a `component:` version names a
release, and a tag may exist without one, so the releases list never proves a version absent.

**Self-hosted instances.** `include: - project:` carries **no host segment in GitLab's
own syntax at all** — the instance is always implicit. Set
`registries.gitlab_instance_host` to the host such an include (and a
`$CI_SERVER_FQDN`-relative `component:` include) should resolve against:

```json
{
  "registries": {
    "gitlab_instance_host": "gitlab.mycorp.dev"
  }
}
```

Left unset, both forms are parsed (the include reference is still shown in hover) but
not version-resolved — an informational diagnostic explains why and names this setting
as the remedy. No default host is ever guessed and no git-remote inference is performed:
an incorrect guess would show version data from the wrong GitLab instance.

**Blocked by policy is a distinct diagnostic from unset.** When the configured
instance host (or an inline `component:` host) is rejected by
`registries.workspace_registries` (see [Cargo](cargo.md#customprivate-registries), issue
#967), the diagnostic names the blocked host class instead of the generic "set
`registries.gitlab_instance_host`" message — the setting is already correct in that case,
so telling the user to set it would be wrong advice. Two `component:` hosts differing only
in letter case are grouped under one diagnostic, since hostnames are case-insensitive.

**The one host `GITLAB_TOKEN` is ever sent to.** The token's destination comes from the
process environment, never from `registries.gitlab_instance_host`: editors merge a cloned
repository's own settings into that value (see
[Editor workspace settings and trust](../configuration.md#editor-workspace-settings-and-trust)),
and a GitLab Personal/Project Access Token is only ever valid for the instance that issued it.
With `GITLAB_TOKEN_HOST` unset, `GITLAB_TOKEN` is sent only to `gitlab.com`; with
`GITLAB_TOKEN_HOST=gitlab.mycorp.dev` exported next to `GITLAB_TOKEN`, it is sent only there —
a `component:` include naming `gitlab.com` in that same file is fetched unauthenticated. An
invalid `GITLAB_TOKEN_HOST` (a port, scheme, path, a trailing dot, or a non-punycode
internationalized name) disables the token entirely, with a warning in the log, rather than
falling back to `gitlab.com`. An empty `GITLAB_TOKEN_HOST` is treated as unset, so the token is
bound to `gitlab.com`. A `401`/`403` from a host the token is not bound to shows a hint to set
`GITLAB_TOKEN_HOST` if the instance is self-hosted.
`gitlab.com` and the `GITLAB_TOKEN_HOST` host are operator-trusted and use the baseline policy
tier: a public-looking name that resolves to a private address (split-horizon DNS, common for a
self-hosted instance) is reachable there, and the system proxy applies. A private IP-literal host
stays blocked.
`registries.gitlab_instance_host` still drives host resolution, unauthenticated unless it names
the same host as `GITLAB_TOKEN_HOST`. Every other literal host a `component:` include names is
always fetched unauthenticated, subject to the same
`registries.workspace_registries` `HostClass` policy gate every other ecosystem's
workspace-declared host goes through. A host that resolves to a blocked address class at
connect time shows the policy-specific message described under
[Cargo](cargo.md#customprivate-registries).

A `workspace/didChangeConfiguration` that changes `registries.gitlab_instance_host`
re-parses every already-open GitLab CI document immediately, the same as
`registries.workspace_registries` and `registries.nuget_user_profile_sources`
(issue #592) — no edit or reopen needed for the new host to take effect.

**Per-document host cap.** At most 8 distinct literal `component:` hosts are resolved
per document; a further distinct host is logged once and left unresolved — this bounds
the per-`didOpen` connection fan-out a single file's content could otherwise drive
unbounded.

## Mutable-Ref Pinning

GitLab CI/CD shares its mutable-ref-pin diagnostic and bulk "Pin All to SHA" code lens with
GitHub Actions — see [CI/CD Pinning](../cross-ecosystem/ci-pinning.md) for the full detail.

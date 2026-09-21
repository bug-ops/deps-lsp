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

**The one host `GITLAB_TOKEN` is ever sent to.** `registries.gitlab_instance_host`
*replaces*, not joins, `gitlab.com` as the token's destination — a `component:` include's
host segment is content read out of a checked-in manifest, so a cloned repository could
otherwise direct the token to a host of its choosing, and a GitLab Personal/Project
Access Token is only ever valid for the instance that issued it. Concretely: with the
setting unset, `GITLAB_TOKEN` is sent only to `gitlab.com`; once set to
`gitlab.mycorp.dev`, it is sent only there — a `component:` include naming `gitlab.com`
in that same file is fetched unauthenticated. Every other literal host a `component:`
include names is always fetched unauthenticated, subject to the same
`registries.workspace_registries` `HostClass` policy gate every other ecosystem's
workspace-declared host goes through.

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

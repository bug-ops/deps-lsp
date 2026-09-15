# CI/CD Pinning

These two features are specific to GitHub Actions and GitLab CI/CD — the two YAML-based CI/CD
ecosystems where a dependency reference is commonly a mutable tag or branch rather than a
version range.

## Mutable-Ref-Pin Diagnostic (issue #473, #634)

A dependency or include pinned to a mutable ref can silently
start running different code than the workflow/manifest file shows: a compromised or republished tag
changes what CI executes without a single line of the file changing. This is a distinct, additive
signal from the outdated-version diagnostic (configurable via
`diagnostics.mutable_ref_pin_severity`, default HINT) — a pin can be up to date on its tag and
still vulnerable to tag mutation, so both diagnostics can fire independently on the same target
with distinct codes:

**GitHub Actions:** A `uses:` step pinned to a mutable ref — a tag (`actions/checkout@v4`)
or, in a future iteration, a branch — is flagged via this diagnostic:

```
actions/checkout is pinned to the mutable tag ref `v4`; pin to a full commit SHA to guard against tag mutation
```

**GitHub Actions:** The diagnostic fires for two kinds of tags:
- **Semantic-version-shaped tags** (`v1.2.3`, `v4.0`, etc.) — detected by text pattern and confirmed via the registry.
- **Literal-named tags** (non-version-like names such as `cargo-deny`, `latest-stable`) — these do not look tag-shaped to the parser, but when the registry confirms they are real tags, they become eligible for this diagnostic too (issue #551).

**"Pin `<name>` to commit SHA" quick fix (GitHub Actions).** When offered, rewrites the step's ref to
`<sha> # <tag>` — the exact same `{sha} # {tag}` shape the outdated-SHA-update quick fix already
produces for a SHA-pinned step, reusing the tag/SHA cross-reference already populated by the
existing outdated-version check (zero new network calls). The quick fix is withheld, not offered
with a wrong or destructive edit, in three cases:

- The tag's commit SHA is not yet known — e.g. the document was opened before the registry fetch
  completed, or the tag was moved/deleted/is not a full `major.minor.patch` release the registry
  indexes (a moving major-version ref like `v4` itself is frequently in this category — GitHub's
  tags API lists `v4.3.1`, not a synthetic `v4` tag object).
- **For literal-named tags**, even if the SHA is known, the quick fix is deliberately withheld (safety boundary FR-005) — a literal tag name like `cargo-deny` could in principle be a typo for a branch name, and silently replacing it with an auto-rewritten SHA would lock workflow behavior in place without the author's explicit intent. The diagnostic still fires so you know the tag is mutable, but the fix requires manual intervention to avoid accidental branch/tag confusion.
- The `uses:` value is a **quoted YAML scalar** (`uses: "actions/checkout@v4"`). The ref text
  sits inside the quotes there, so appending `# <tag>` would place a `#` inside the string rather
  than starting a YAML comment — a `uses:` value GitHub Actions rejects. Re-pin a quoted step by
  hand, or remove the quotes first.

**Out of scope for GitHub Actions this iteration:** branch pins (`@main`) get no diagnostic yet — no
tag-to-SHA-style index exists for branches, and adding one would require a new network call per
branch; reusable-workflow calls (`owner/repo/.github/workflows/x.yml@ref`) and `./local`/
`docker://` references are not resolvable refs and get no diagnostic either.

**GitLab CI/CD:** The diagnostic fires for:
- **`include: - project:`** pins to a mutable tag or branch ref — the ref is resolved against the GitLab
  repository-tags API. The diagnostic fires for tag-shaped refs (semantically-versioned or literal-named
  tags confirmed as real).
- **`include: - component:`** pins to `~latest` or a partial-semver version (e.g. `1.2` for a component
  published via releases) — while not a branch-vs-tag confusion risk like GitHub Actions, these are still
  mutable in the sense that the pin can resolve to a different release if the GitLab project publishes a
  new one (resolved against the project-releases API).

**"Pin to commit SHA" quick fix (GitLab CI/CD).** For `project:` includes, rewrites the tag/branch ref to
its resolved commit SHA; for `component:` includes with `~latest`/partial pins that have already been
resolved against the releases API, shows the fix was available (resolves #643). The quick fix is withheld in
the same cases as GitHub Actions: SHA not yet known (still loading), or for literal-named tags (same
branch/tag ambiguity safety concern).

Unlike every other diagnostic in this project, severity alone cannot silence this one —
`DiagnosticSeverity` has no suppression value. Set `diagnostics.mutable_ref_pin_enabled` to
`false` in initialization options to turn it off entirely for teams that intentionally accept
mutable pins.

## Bulk "Pin All to SHA" Code Lens (issue #633, generalized cross-ecosystem in #640)

A document with at least one mutable-ref pin resolvable to a commit SHA shows a second
code lens alongside `Update N outdated dependencies`, titled `Pin N {noun} to commit
SHA` (GitHub Actions: `Pin N actions to commit SHA`; GitLab CI: `Pin N refs to commit
SHA`). Clicking it rewrites every such pin in one batch edit — the bulk counterpart of
the per-position "Pin `<name>` to commit SHA" quickfix each ecosystem already offers.
The lens/command itself is a shared `deps-lsp`/`deps-core` mechanism
(`Ecosystem::collect_pin_all_to_sha_edits`); an ecosystem with no mutable-ref pin concept
simply never shows it.

**GitHub Actions:** reuses the exact same `TagIndex` lookup the per-step quickfix uses
(**zero additional network calls**: bulk-pinning N actions costs N hashmap lookups, not N
registry fetches).

A step is included only when the per-step quickfix would also offer it — the bulk lens is
never laxer than the single-step fix:

- Only a statically-classified `PinStyle::Tag` step is pinned; a registry-confirmed
  literal-named tag (the `PinStyle::Branch` case from the diagnostic section above) has no
  automated fix here either, for the same branch/tag name-collision safety reason.
- A step whose tag has no resolvable `TagIndex` entry yet (cache miss — e.g. the document
  was opened before the registry fetch completed) is silently skipped, not blocked on or
  turned into an extra fetch.
- A quoted `uses:` scalar (`uses: "actions/checkout@v4"`) is skipped, matching the
  per-step quickfix's own guard against corrupting the quoted value.
- A `uses:` step written in YAML **flow** style (`{uses: actions/checkout@v4, with:
  {node: 20}}`) is skipped: appending `# <tag>` right after the ref would comment out the
  rest of the flow collection, producing invalid (unterminated) YAML instead of merely
  leaving the step unpinned. Ordinary block-style steps — the overwhelming majority of
  real workflows — are unaffected.

The lens itself is omitted entirely — no permanent line-0 annotation — when nothing in the
document is eligible: an all-SHA-pinned workflow, an empty workflow, or one where every tag
is still an unresolved cache miss. It is also omitted whenever
`diagnostics.mutable_ref_pin_enabled` is `false` — the same on/off switch that silences the
mutable-ref-pin diagnostic above, since a lens is permanently rendered (unlike the pull-based
per-step quickfix) and must respect the same opt-out.

**Known limitations.** The lens counts only steps resolvable via the live `TagIndex`, while
the mutable-ref-pin diagnostic flags every `PinStyle::Tag` step regardless of resolvability —
so a workflow can show more mutable-ref-pin squiggles than the lens's own count, and clicking
the lens can leave some squiggles in place (the steps it genuinely could not resolve). The
lens's displayed count can also drift from the number of edits actually applied if a
background fetch for another open workflow evicts a `TagIndex` entry between render and
click (the shared index is bounded to 256 repositories).

**GitLab CI:** covers a `project:`/`component:` include pinned via `PinStyle::Tag`
(resolved synchronously against the shared `TagIndex`, same as GitHub Actions) *and* a
`component:` include pinned via `~latest`/a partial version (`1.2`), resolved against the
project's already-fetched release list — the lens never itself performs a network fetch,
so a `~latest`/partial pin is only counted (and edited) once that data has already been
loaded for some other reason (e.g. hover, diagnostics). A SHA pin, an unconfirmed branch
ref, and a ref-less `project:` include are never eligible, matching the per-position
quickfix's own restrictions.

See also [GitHub Actions](../ecosystems/github-actions.md) and
[GitLab CI/CD](../ecosystems/gitlab-ci.md) for the rest of each ecosystem's own features.

# GitHub Actions

## Basics

Unlike the language-package ecosystems above, GitHub Actions is a **CI/CD supply-chain pinning**
ecosystem: `deps-lsp` does not track library dependencies, it tracks which commit of a
third-party Action each workflow step trusts. Two manifest shapes are recognized:

- **`.github/workflows/*.yml`/`*.yaml`** — ordinary workflow files, matched via a
  directory-pattern rule (any file in that directory with a `.yml`/`.yaml` extension), not an
  exact filename.
- **`action.yml`/`action.yaml`** — a composite/reusable Action's own metadata file, whose
  `runs.steps` can itself reference other Actions.

Every `uses:` step is a dependency:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v4.1.1
```

A tag reference (`@v4`) resolves against **GitHub's own tags API** for that `owner/repo` (no
separate package registry exists for Actions) and is flagged by the mutable-ref-pin diagnostic,
since a tag can be force-moved by the repository owner to point at different code without the
version string in your workflow ever changing — see [CI/CD
Pinning](../cross-ecosystem/ci-pinning.md) for why this matters and how the SHA-pinning code
action/code lens works. A full 40-character commit SHA is the only pin GitHub itself cannot
silently repoint.

## Non-Semver Tag Handling (issue #550)

When a GitHub Action repository has only tags that don't parse as full semantic versions — such as
`dtolnay/rust-toolchain` with its sole tag `v1`, or literal-named tags like `cargo-deny` — the
hover and diagnostics handle these gracefully instead of showing a false "Unknown package"
diagnostic.

- **Hover**: shows the package as resolvable (not unknown), but with an empty "Recent versions" list since no tag matches the standard semver filter. The mutable-ref-pin diagnostic still fires for the tag ref even though no update-to-latest is available.
- **Diagnostics**: the package is recognized as resolvable, not reported as "Unknown package" — this is a real action, just not one with a conventional semver release train.
- **Literal-named tags** (non-version-like names): are now recognized as actual tags (when confirmed by the registry) and qualify for the mutable-ref-pin diagnostic, even though they don't follow the `major.minor.patch` or `v\d+` patterns the parser heuristic would normally detect.

## SHA-Pin Comment Tag Freshness (issue #907)

A SHA-pinned step commonly carries a human-readable trailing comment naming the
tag it was pinned from (`uses: actions/checkout@<sha> # v4`). This comment is
accepted at **partial precision** too — `# v6`, `# v2.9` — not just a full
`major.minor.patch` tag; `is_partial_semver_shaped` (`deps-core`'s `git_ref`
module) is the acceptance gate, stricter than the git-ref-oriented
`is_tag_shaped` so free-text comments (a date, an issue number) aren't mistaken
for a tag.

The comment is treated as a hint, not ground truth: hover, diagnostics, inlay
hints, and the bulk "update outdated" code lens all resolve the pin's actual
freshness against `TagIndex.sha_to_tag` (which SHA the tag *really* points at
today), so a comment that has drifted from the pinned SHA no longer produces a
false "up to date" result just because the comment text looked current.

A full-SHA pin that no release tag points at (with no comment, or a non-version one like
`# cargo-deny`) is reported as outdated once the repository's tags are loaded; a pin to a
non-release commit is therefore offered the latest release. This includes a commentless pin on a
non-release commit newer than the latest release: it is reported outdated and update-all re-pins
it to the latest release (effectively a downgrade).

A pin whose SHA is absent from the loaded tag index is reported outdated even when it carries a
version comment, since the comment cannot make a non-release commit the latest release. The
"absent" verdict is only drawn from a complete tag list: a repository with more tags than the
fetch cap (30 pages of 100) yields a truncated index, and a SHA missing from it stays
unverifiable (comment trusted, no mismatch diagnostic) instead of being called outdated.

### Comment mismatch diagnostic (issue #1722)

When the trailing comment names a tag that is provably not the pinned commit's tag, the
`sha-comment-mismatch` diagnostic flags the step (an imposter-commit or stale-comment signal) and
hover adds a `**Warning**` line, either `comment says v2.87.20, but SHA is v2.87.22` or
`SHA is not the commit of any release tag`. A partial-precision comment (`# v4`) agrees with a
SHA whose most specific tag extends it. Nothing is reported while the tag index is cold or when
the SHA is absent from a truncated index. Severity defaults to warning and is set with
`diagnostics.sha_comment_mismatch_severity`; there is no on/off toggle.

### Updating quoted and flow-style pins (issue #1724)

Update-all and the update quickfix rewrite a plain scalar SHA pin to `<new sha> # <tag>`. For a
quoted or flow-style pin (`uses: 'owner/repo@<sha>'`, `{uses: owner/repo@<sha>, with: {...}}`)
only the 40-hex SHA is replaced, so the quoting and flow structure stay intact. A trailing
`# vX` comment outside the quotes is not touched and may be left stale.

## Mutable-Ref Pinning

GitHub Actions shares its mutable-ref-pin diagnostic and bulk "Pin All to SHA" code lens with
GitLab CI/CD — see [CI/CD Pinning](../cross-ecosystem/ci-pinning.md) for the full detail.

## Release-Freshness Coverage (shared with Swift)

GitHub Actions sources release dates from the same `deps_core::github::ReleaseDatesCache` Swift
uses — see [Swift](swift.md#release-freshness-coverage-shared-with-github-actions) for the full
detail, including the four ways this coverage is partial and the `GITHUB_TOKEN` requirement.

## Vulnerability Scanning

OSV.dev does not version-match the `GitHub Actions` ecosystem server-side (a versioned query
returns nothing even for an affected version), so deps-lsp fetches a package's advisories
without a version and matches their affected ranges locally against the pinned version.

- A full SemVer pin (`@v4.1.2`, or a SHA pin whose tag resolves to one) is checked; an advisory
  whose range contains it produces the usual vulnerability hover and diagnostic.
- A floating tag (`@v4`, `@v4.1`) is resolved through the commit the tag currently points at, using
  the same tags fetch as SHA pins: the most specific release tag on that commit that extends the
  written tag (`v4.2.2` for `@v4`) is the version that is checked, and hover shows it as
  `Resolved`. This is a snapshot taken at scan time: if the tag later moves to another commit,
  the result is refreshed only when the tags are next fetched. If the commit carries no such
  release (for example only `v4`, or an unrelated `v5.0.0`), the tag index is not loaded yet, or
  the pin is a bare major (`@4`), a SHA pin with no resolvable tag, or any other non-SemVer pin,
  it is shown as "not checked", never as clean.
- A commit often carries several release tags (`v4.8.0` and `v4.9.0`). Every one of them is
  checked, so an advisory that affects only a sibling tag is still reported, and hover and the
  diagnostic name it (`matched release tag v4.9.0`). For a SHA pin all release tags on the commit
  count; for an exact tag pin (`@v4.8.0`) only the releases of the same major version do, and
  for a floating tag (`@v4`) only the releases that extend the written tag. Pre-release tags are
  never checked as siblings. A sibling-only advisory whose fix is not newer than the pinned
  version is not offered as a fix.
- An advisory exists for the package but its affected range cannot be evaluated: a diagnostic
  notes that vulnerability data was not checked (`UnevaluableAdvisoryRange`).
- A package with more than 50 advisories is reported as truncated rather than partially matched.

OSV.dev package names are case-sensitive, so the queried name is the repository's canonical
`owner/repo` casing taken from the GitHub tags response (a lowercase `uses:` value still
matches). Vulnerability checking therefore depends on the GitHub tags fetch and its API quota
(60 requests/hour unauthenticated; set `GITHUB_TOKEN` to raise it).

Until the casing is confirmed (or when the tags fetch fails or the repository is private), the
name as written in the manifest is queried instead, and only a positive result is trusted: an
advisory found under the written name is reported, while an empty or non-matching answer stays
"not checked" (`CanonicalNameUnconfirmed`), never clean. Such a result is re-checked under the
canonical casing once the tags arrive, and a recommended fix is not offered as verified for it.
Because of this fallback, the written `owner/repo` of a private repository is sent to osv.dev
whenever its canonical name cannot be confirmed, as it was before canonical-name resolution.

**Known limitations**: a renamed or transferred repository is queried only under its current
GitHub name once confirmed, so an advisory OSV.dev still files under the old name is not
matched.

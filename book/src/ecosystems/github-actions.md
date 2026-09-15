# GitHub Actions

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

## Mutable-Ref Pinning

GitHub Actions shares its mutable-ref-pin diagnostic and bulk "Pin All to SHA" code lens with
GitLab CI/CD — see [CI/CD Pinning](../cross-ecosystem/ci-pinning.md) for the full detail.

## Release-Freshness Coverage (shared with Swift)

GitHub Actions sources release dates from the same `deps_core::github::ReleaseDatesCache` Swift
uses — see [Swift](swift.md#release-freshness-coverage-shared-with-github-actions) for the full
detail, including the four ways this coverage is partial and the `GITHUB_TOKEN` requirement.

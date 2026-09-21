# Swift

## Basics

Swift Package Manager has no manifest data format — `Package.swift` is literal, executable
Swift source code, not TOML/JSON/YAML. `deps-swift` does not run a Swift compiler; it extracts
`.package(url:, ...)` calls with a set of targeted patterns covering every requirement form SPM
supports:

```swift
dependencies: [
    .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),          // upToNextMajor
    .package(url: "https://github.com/apple/swift-collections.git", .upToNextMinor(from: "1.1.0")),
    .package(url: "https://github.com/apple/swift-nio.git", .exact("2.65.0")),
    .package(url: "https://github.com/apple/swift-atomics.git", branch: "main"),
    .package(url: "https://github.com/apple/swift-algorithms.git", revision: "abc123..."),
]
```

Since Swift Package Manager has no registry of its own for GitHub-hosted packages, versions
are resolved from the same host the `url:` points at: **GitHub's tags API**, via
`deps_core::github`'s shared client (also used by GitHub Actions — see below). A `.branch`/
`.revision` dependency is not version-resolvable at all and is shown as a non-registry `Git`
source with no hover version data. When a `Package.resolved` lock file is present alongside
the manifest, it is read to show each dependency's actual pinned (in-use) revision/version.

## Non-GitHub Package Hosts (issues #979, #983, #924)

A registry-form `.package(url: "...")` dependency is only ever resolved against
GitHub's API (`deps-swift` has no other registry client), so `url_to_identity`
now parses the URL's host and produces a GitHub `owner/repo` identity **only**
when the host is `github.com`/`www.github.com`. A dependency declared against
any other host — GitLab, a self-hosted git server, or any private host,
including `git@host:path` SSH-form URLs — falls back to a visible
`DependencySource::Git` with the raw URL (matching the existing
`.branch`/`.revision` behavior) instead of vanishing from parse results or,
worse, being silently resolved against an unrelated, attacker-nameable GitHub
repository with the user's `GITHUB_TOKEN` attached to the request.

Because this source is a non-resolvable `Git` dependency, no diagnostic fires
for it at all — `validate_package_name` accepts non-GitHub URLs (mirroring
`deps-github-actions`'s precedent for non-resolvable sources) instead of showing
a misleading "name must be a GitHub `owner/repo` identifier" error that implied
the manifest itself was wrong.

## Release-Freshness Coverage (shared with GitHub Actions)

Unlike the ecosystems whose registry already carries a publish timestamp, Swift and [GitHub
Actions](github-actions.md#release-freshness-coverage-shared-with-swift) both source package
versions from GitHub's `tags` API, which has no date field. `deps-swift` and
`deps-github-actions` each augment their tag-derived version list with publish times from
GitHub's *releases* API (one extra request per package, memoized behind a TTL) via the same
shared `deps_core::github::ReleaseDatesCache` (#486) — but this makes both ecosystems'
freshness signal **partial**, in four distinct ways:

- **Requires `GITHUB_TOKEN`.** Without it, hover and completion render versions exactly as they
  did before this feature — no publish age shown, no error. A one-time `tracing::info!` notes the
  skip on first use (`export GITHUB_TOKEN=$(gh auth token)` to enable it).
- **Covers only versions with a matching GitHub Release.** A tag with no corresponding Release
  shows no date. Coverage of the versions actually rendered is high but not universal even among
  recent versions — one real-world counterexample (`SwiftyJSON/SwiftyJSON`) is missing dates for
  two of its eight most recent tags.
- **Reports Release *publish* time, not tag-creation time.** If a maintainer tags a commit and
  only publishes the GitHub Release for it later, the date reflects the Release, which can read
  as more recent than when the code was actually written. There is no cheap way to distinguish
  this from a genuinely fresh release.
- **Covers roughly the 100 newest releases only** (one unpaginated API page). Browsing completions
  filtered to an older major version line can show no dates at all, even though the same package's
  newest versions do — this is a known, accepted inconsistency within a single session.

A miss in any of the above degrades to no date shown, never a wrong one. GitHub Actions inherits
this coverage verbatim (same shared cache, same `/releases` endpoint) — the one difference is the
join key: a GHA `uses:` step's tag keeps its `v` prefix as published in the version list, so the
join normalizes it before matching against the releases map, while Swift's tag-derived versions
are already normalized at parse time.

## Licensing

Swift's license comes from a per-ecosystem background pre-fetch (GitHub's `licensee`-detected
`license.spdx_id`) rather than the hot-path registry response — see [License
Hover](../cross-ecosystem/licensing.md#license-hover) for the full cross-ecosystem picture.

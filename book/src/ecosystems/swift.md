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

A `traits:` argument (SwiftPM 6.1) of any shape is accepted after the requirement; its value is
never parsed. A `.package(id: "scope.name", from: "1.0.0")` registry dependency (SE-0292) is
resolved through the registry its scope maps to; see
[Package Registries (SE-0292)](#package-registries-se-0292).

## Package Registries (SE-0292)

SwiftPM has no public default registry, so an `id:` dependency is only version-resolved when its
scope (or a `[default]` entry) maps to a registry in a `registries.json` file, the same file
`swift package-registry set` writes:

```json
{
  "registries": {
    "[default]": { "url": "https://tuist.dev/api/registry/swift" },
    "acme": { "url": "https://swift.acme.dev/api" }
  },
  "authentication": { "swift.acme.dev": { "type": "token" } },
  "version": 1
}
```

`GET {url}/{scope}/{name}` is sent with `Accept: application/vnd.swift.registry.v1+json` using the
lowercase identity (`Apple.Swift-NIO` is requested as `apple/swift-nio`; scopes match
case-insensitively). Releases whose key is not semver are skipped; a release with a `problem` is
marked yanked. With no matching entry the dependency is shown but never fetched, and an `id:` name
is never sent to GitHub or any other registry.

### Configuration tiers

| Tier | Path |
|------|------|
| Project | `<directory of Package.swift>/.swiftpm/configuration/registries.json` (no ancestor walk) |
| User (macOS) | `~/Library/org.swift.swiftpm/configuration/registries.json` |
| User (other) | `$XDG_CONFIG_HOME/swiftpm/configuration/registries.json` if `XDG_CONFIG_HOME` is set, else `~/.swiftpm/configuration/registries.json` |

The project tier overrides the user tier per scope and for `[default]`; a scoped entry in either
tier wins over `[default]`. Exactly one user-tier path is read, with no existence fallback; an
empty or relative `XDG_CONFIG_HOME` makes the user tier unusable. The file is decoded with
SwiftPM's strictness (`version` must be `1`, scope keys must follow the scope grammar,
`authentication.type` must be `basic` or `token`, `security` must be an object when present, unknown
keys are ignored). A tier that exists but is unusable (unreadable, not a regular file, over 8 MiB,
or failing that decode) leaves every `id:` dependency unresolved with a warning; it never falls
back to the other tier's `[default]`.

On Unix, a `.swiftpm` that is a regular file (or any other stat failure besides "not found") also
makes the project tier unusable, which fails closed; Windows reports "not found" for that path, so
the project tier is simply absent there. The user-level file is not watched: edits to it
(and to `SWIFTPM_REGISTRY_*` variables, read once at startup) take effect on the next manifest
parse, not immediately; only a change to the project's
`.swiftpm/configuration/registries.json` triggers a reparse (an unrelated `registries.json` elsewhere in the workspace does not).

### Trust and credentials

A registry URL is **trusted** exactly when it equals (after normalization: lowercase host, default
port and trailing `/` dropped, path case kept) a URL declared in the *user-level* file, whichever
tier declared it in the current workspace. Any other URL is **workspace-declared**. Trust never
depends on the workspace, so a hostile repository cannot redirect a credential.

| | Trusted | Workspace-declared |
|---|---------|--------------------|
| Reachability | exempt from `registries.workspace_registries` (like Cargo's `$CARGO_HOME`), except loopback, link-local, cloud-metadata, unspecified and reserved hosts, which are never fetched | gated by `registries.workspace_registries` |
| Redirects | confined to the registry's base URL | confined to the registry's base URL |
| Credential | attached | never attached |

Credentials are read once at startup from `SWIFTPM_REGISTRY_TOKEN`, or from
`SWIFTPM_REGISTRY_LOGIN` together with `SWIFTPM_REGISTRY_PASSWORD` (the token wins; one variable of
the pair alone is ignored with a warning naming it). The header format comes from the user-level
`authentication` map only: `token` (or no entry) sends `Bearer`, `basic` sends `Basic`; a login of
`token` with no entry is also sent as `Bearer`, as SwiftPM does. `authentication` is keyed by host and
non-default port, like SwiftPM (`swift.acme.dev:8443` does not match a portless key); unlike
SwiftPM, an explicit default port (`:443`) is treated as absent. netrc and macOS Keychain
credentials are not read.

**The single environment credential is sent to every trusted registry URL**, including a public
`[default]` listed in the user-level file next to a private scoped registry. If you do not want
the token sent to a public registry, do not list it in the user-level `registries.json` while the
variable is exported (declare it in the project file instead).

### Deviation from SwiftPM

Released SwiftPM 6.4.x sends environment credentials to every host; SwiftPM `main` (since
swiftlang/swift-package-manager#10507, unreleased) binds them to the origins of every configured
registry across both tiers, project tier included. `deps-swift` is stricter: user-tier provenance
plus an exact full-URL match, so path-tenanted shared hosts (`host/api/swift/<repo>`) never receive
another tenant's credential. A project-only registry on a host you trust therefore gets `401`
here where SwiftPM `main` would authenticate; add that exact URL to your user-level file. The
authentication type is also taken from the user tier only, and workspace-declared URLs are
policy-gated, which SwiftPM does not do.

### Limitations

- **Paginated release lists.** A response carrying `Link: <...>; rel="next"` is discarded and the
  dependency shows "registry paginates its release list; pagination is not supported yet" (#1754); no
  latest version or up-to-date mark is derived from a partial page.
- A project-declared hostname that resolves to a blocked address class shows the generic
  fetch-failure message rather than a policy-specific one.
- No `id:` name completion (SE-0292 has no search endpoint) and no `publishedAt` freshness.

`Package.resolved` `registry` pins are shown as registry sources, and a pin of an unrecognized
`kind` is skipped instead of being treated as a source-control pin.

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

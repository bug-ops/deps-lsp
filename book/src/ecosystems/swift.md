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
SwiftPM, an explicit default port (`:443`) is treated as absent.

When the variables are unset, credentials come from the content of `SWIFTPM_NETRC_DATA`, else from
`~/.netrc` (the first source that exists wins, as in SwiftPM). On macOS, the opt-in
[Keychain source](#macos-keychain-credentials) sits between `SWIFTPM_NETRC_DATA` and `~/.netrc`. A netrc
is matched by the registry's host, ignoring the port, and is sent as `Basic` unless the
user-level `authentication` entry says `token` (or the login is `token`). `SWIFTPM_NETRC_DATA`
is parsed once at startup, first matching machine wins and host names compare case-sensitively;
an unusable value logs a warning naming only the variable and is skipped. `~/.netrc` is re-read
whenever it changes, the last matching machine wins and host names compare case-insensitively; an
absent or invalid file yields no credential. The grammar follows SwiftPM's `Netrc.swift`
(quoted values, `#` comments after whitespace, `account` between login and password, entries
missing a login or password dropped).

**A single credential is sent to every trusted registry URL**, including a public `[default]`
listed in the user-level file next to a private scoped registry. If you do not want a token
sent to a public registry, do not list it in the user-level `registries.json` while the variable
is exported (declare it in the project file instead). With netrc the credential depends on the
host, but a `default` entry applies to every trusted host without a `machine` entry, public
registries included. On Linux, and from `SWIFTPM_NETRC_DATA` on every platform, a `default` entry
is honored; on macOS the `default` entry of `~/.netrc` is ignored.

### Deviation from SwiftPM

Released SwiftPM 6.4.x sends environment credentials to every host; SwiftPM `main` (since
swiftlang/swift-package-manager#10507, unreleased) binds them to the origins of every configured
registry across both tiers, project tier included. `deps-swift` is stricter: user-tier provenance
plus an exact full-URL match, so path-tenanted shared hosts (`host/api/swift/<repo>`) never receive
another tenant's credential. A project-only registry on a host you trust therefore gets `401`
here where SwiftPM `main` would authenticate; add that exact URL to your user-level file. The
authentication type is also taken from the user tier only, and workspace-declared URLs are
policy-gated, which SwiftPM does not do.

On macOS SwiftPM reads credentials from the Keychain and not from `~/.netrc` (unless forced).
`deps-swift` reads `~/.netrc` there by default, ignoring its `default` entry; set
`registries.swift_keychain_credentials` to also read the Keychain, as described next.

### macOS Keychain credentials

Set `registries.swift_keychain_credentials` to `"enabled"` (default `"disabled"`) to let
`deps-swift` look up a registry credential in the macOS login Keychain, the way SwiftPM does:

```json
{ "registries": { "swift_keychain_credentials": "enabled" } }
```

Credential sources have the order `SWIFTPM_REGISTRY_*` environment variables,
`SWIFTPM_NETRC_DATA`, Keychain, `~/.netrc`, and, like SwiftPM, only the first source that applies
is used. With the setting enabled on macOS, `~/.netrc` is therefore never read, and a Keychain
miss for a host does not fall back to the netrc: a registry whose credential lives only in
`~/.netrc` loses it until you disable the setting. The setting has no effect on other platforms (a warning
is logged and `~/.netrc` is used), and an enabled setting never sends a credential to a
workspace-declared registry: the Keychain is consulted only for user-declared (trusted) registry
URLs, with the same header format rules as the other sources.

**What happens at the first request.** The lookup runs `/usr/bin/security find-internet-password`
for the registry's host (and port, only when the URL names one). Reading the secret can make macOS
show an access prompt, and the lookup waits up to 10 minutes for you to answer it; lookups are
serialized, so only one prompt is open at a time, and a server queued behind another's prompt does
not spend its own 10 minutes while it waits. Offline mode (`network.offline`) never runs
`security`. The registry
request is not sent until the lookup finishes, but the surrounding version fetch has its own,
much shorter timeout, so the dependency shows a fetch failure while the prompt is open. Once you
approve and the answer arrives after that fetch gave up, open Swift documents are refreshed
automatically and the credential is used; no editor action is needed.

Answer the prompt with "Allow", not "Always Allow". The server remembers the secret for the life
of the process, so "Allow" prompts once per server start. "Always Allow" adds `/usr/bin/security`
(not `deps-lsp`) to the item's access list, after which any process running as your user can read
the secret silently with `security find-internet-password -w`. Because a cloned repository's
workspace settings can enable this setting (see the caveats below), expect the prompt only for
registries you declared yourself.

**What is remembered.** Per registry host, for the life of the process unless noted:

| Outcome | Kept |
|---|---|
| Item found | until exit; disabling the setting drops it immediately and aborts a pending lookup |
| No item | 5 minutes, then looked up again |
| Access refused (any `security` failure other than not found and interaction-not-allowed) | until the setting is toggled off and on, or the server restarts |
| Timeout, or exit 36 (interaction not allowed, for example a locked keychain without UI) | not remembered; retried on the next fetch |

A `401` never triggers a new lookup, and without a found item no credential is sent.

**Caveats.**

- With several Keychain items for one host, `security` returns the first match, while SwiftPM
  picks the most recently modified item; the two tools can choose different credentials.
- When a registry switches between sending a Keychain credential and none (lookup resolving to found, or any change of the setting), its cached release lists are dropped, so an anonymous response is not served afterwards; this is skipped offline, so the warm offline cache survives.
- A `didChangeConfiguration` payload without a `registries` section resets every `registries`
  setting, including this one, to its default (`"disabled"`), as for the other settings.
- The secret is read with `security ... -g`, so non-ASCII secrets are decoded correctly.
- Without a URL port, the lookup omits `-P`, so an item stored for any port of that host matches.
- The item's account name is passed to `security` as an argument and is visible to other processes
  of your user in the process list; the secret is never passed as an argument and never logged.
- Editor workspace settings (`.zed/settings.json`, `.vscode/settings.json`; see
  [Editor workspace settings and trust](../configuration.md#editor-workspace-settings-and-trust)) in a cloned repository
  can enable this setting and therefore trigger the access prompt. The credential still goes only
  to registries declared in your user-level `registries.json`, never to hosts the repository
  declares.
- `deps-cli` does not support the setting: it exits before a prompt can be answered, so it ignores
  the setting with a warning on stderr. Use the environment variables, `SWIFTPM_NETRC_DATA` or
  `~/.netrc` there.

### Limitations

- **Paginated release lists.** `Link: <...>; rel="next"` pages are followed (at most 10 pages,
  10,000 releases, 32 MiB of response bodies and 15 seconds in total; same origin and path as the
  registry URL, same credential rules) and merged. A missing, ambiguous, repeated or foreign next
  link, or a list over a limit, discards everything fetched and the dependency shows "registry
  returned an unusable next-page link", "registry release list exceeds the page limit" or
  "registry release list took too long to fetch"; no latest version or up-to-date mark is derived
  from a partial list.
  The failure is remembered for 90 seconds. Every page is revalidated on every request, so a merged
  list can be inconsistent only when one page's revalidation fails and that page is served
  from cache.
- **Publication dates.** With freshness enabled, the newest 8 non-yanked releases get their
  `publishedAt` from one metadata request each (`GET {base}/{scope}/{name}/{version}`), at most 4
  at a time and within one 2-second budget per lookup. Dates are remembered for the life of the
  process (a registry's answer for a release does not change); a failed request is retried after
  90 seconds. A missing date never fails the version list.
- A hostname that resolves to a blocked address class shows the policy-specific message described
  under [Cargo](cargo.md#customprivate-registries).
- No `id:` name completion (SE-0292 has no search endpoint).

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

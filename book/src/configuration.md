# Configuration

`deps-lsp` is configured entirely through LSP `initializationOptions` (and updated live via
`workspace/didChangeConfiguration`) — there is no separate config file. The
[README](https://github.com/bug-ops/deps-lsp#readme) shows the most commonly changed options
inline; this page is the exhaustive reference for every section and option.

For the inlay hint icons and the hover/diagnostic/code lens text conventions those options
control, see [Conventions](cross-ecosystem/conventions.md).

## Configuration Reference

| Section | Option | Default | Description |
| --------- | -------- | --------- | ------------- |
| `cache` | `enabled` | `true` | Whether the HTTP entry-map cache is used at all; `false` fetches fresh on every request and never stores. Overridden to behave as `true` while `network.offline` is set |
| `cache` | `fetch_timeout_secs` | `5` | Per-package fetch timeout (1-300 seconds) |
| `cache` | `max_concurrent_fetches` | `20` | Concurrent registry requests (1-100) |
| `loading_indicator` | `enabled` | `true` | Show loading feedback during fetches |
| `loading_indicator` | `fallback_to_hints` | `true` | Show loading in inlay hints if LSP progress unsupported |
| `loading_indicator` | `loading_text` | `"..."` | Text shown during loading (max 100 chars) |
| `code_lens` | `enabled` | `true` | Show the "Update N outdated dependencies" code lens, and (GitHub Actions/GitLab CI, gated additionally by `diagnostics.mutable_ref_pin_enabled`) the bulk "Pin N {noun} to commit SHA" code lens |
| `diagnostics` | `outdated_severity` | `"hint"` | Severity for the outdated-version diagnostic |
| `diagnostics` | `unknown_severity` | `"warning"` | Severity for an unresolvable/unknown package or version |
| `diagnostics` | `yanked_severity` | `"warning"` | Severity for the [yanked-version diagnostic](cross-ecosystem/yanked-and-vulnerabilities.md#yanked-version-diagnostic) |
| `diagnostics` | `unsatisfiable_severity` | `"warning"` | Severity for the [unsatisfiable-requirement diagnostic](cross-ecosystem/version-diagnostics.md#unsatisfiable-version-requirement) |
| `diagnostics` | `deprecated_severity` | `"warning"` | Severity for the [package-deprecation diagnostic](cross-ecosystem/version-diagnostics.md#package-deprecation-diagnostics-issue-205) |
| `diagnostics` | `mutable_ref_pin_severity` | `"hint"` | Severity for the [mutable-ref-pin diagnostic](cross-ecosystem/ci-pinning.md#mutable-ref-pin-diagnostic-issue-473-634) (GitHub Actions/GitLab CI) |
| `diagnostics` | `mutable_ref_pin_enabled` | `true` | Turns the mutable-ref-pin diagnostic and its bulk code lens off entirely — unlike the other diagnostics, severity alone cannot silence it |
| `diagnostics` | `vulnerabilities_enabled` | `true` | Whether OSV.dev-backed vulnerability diagnostics run at all |
| `freshness` | `enabled` | `true` | Flag a "latest" version still inside its cooldown window |
| `freshness` | `cooldown_secs` | `259200` | Cooldown window in seconds (3 days), clamped to 0-30 days |
| `registries` | `workspace_registries` | `"public_only"` | Which workspace-declared registry index hosts are ever fetched, across every ecosystem (Cargo's `.cargo/config.toml`/`[source]`, npm's `.npmrc`, PyPI's `--index-url`/Poetry/uv sources, Go's `$GOENV` `GOPROXY`, NuGet's `NuGet.Config`) — `"public_only"`, `"off"`, or `"all"`; see [Cargo Custom/Private Registries](ecosystems/cargo.md#customprivate-registries), [npm Custom/Private Registries](ecosystems/npm.md#customprivate-registries), [PyPI Custom/Private Indexes](ecosystems/pypi.md#customprivate-indexes), [Go GOPROXY/GOPRIVATE Support](ecosystems/go.md#goproxygoprivate-support), and [NuGet Private/Custom Feeds](ecosystems/nuget.md#privatecustom-feeds). |
| `registries` | `nuget_user_profile_sources` | `false` | Whether a NuGet user-profile-tier `NuGet.Config` source with no repo-declared counterpart becomes a routing hop (`AlternateRegistry`-sourced — OSV/deps.dev/hover-trust suppressed for it), instead of only ever supplying credentials for a matching repo-declared source; see [NuGet Private/Custom Feeds](ecosystems/nuget.md#privatecustom-feeds) |
| `registries` | `gitlab_instance_host` | `""` | The self-hosted GitLab instance host that a `project:` include and a `$CI_SERVER_FQDN`-relative `component:` include resolve against, and the *only* host an optional `GITLAB_TOKEN` is ever sent to — replacing, not joined with, `gitlab.com`. Unset (`""`) means neither form is version-resolved; see [GitLab CI/CD Self-Hosted Instances](ecosystems/gitlab-ci.md#self-hosted-instances) |
| `network` | `offline` | `false` | Block every outbound registry/OSV/GitHub request; already-cached data still serves, uncached dependencies show an offline marker |
| `supply_chain` | `enabled` | `true` | Show the [OpenSSF Scorecard/build-provenance hover line](cross-ecosystem/yanked-and-vulnerabilities.md#supply-chain-trust-signal-issue-543), backed by deps.dev requests; `false` disables the requests and the section entirely |
| `license_policy` | `allow` | `[]` | SPDX identifiers a dependency's license must include at least one of, when non-empty; produces a WARNING diagnostic otherwise. Invalid entries are dropped with a logged warning, not rejected. See [License Policy Diagnostic](cross-ecosystem/licensing.md#license-policy-diagnostic-issue-661) |
| `license_policy` | `deny` | `[]` | SPDX identifiers a dependency's license must not include any of; produces an ERROR diagnostic when matched (wins over `allow`). Invalid entries are dropped with a logged warning, not rejected. See [License Policy Diagnostic](cross-ecosystem/licensing.md#license-policy-diagnostic-issue-661) |
| `typosquat` | `enabled` | `false` | Whether the [typosquat-similarity diagnostic](cross-ecosystem/typosquat-detection.md) runs at all — opt-in, backed by deps.dev's v3alpha `GetSimilarlyNamedPackages`/`GetDependents` endpoints |
| `gossip` | `enabled` | `false` | Whether [deps.dev GOSSIP signals](cross-ecosystem/gossip-signals.md) (Dynamic Cooldown, low-usage) are fetched at all — opt-in, backed by deps.dev's v3alpha `GetFindingsBatch`/`GetFindings` endpoints |

## Full Example

```json
{
  "inlay_hints": {
    "enabled": true,
    "up_to_date_text": "✅",
    "needs_update_text": "❌ {}"
  },
  "diagnostics": {
    "outdated_severity": "hint",
    "unknown_severity": "warning",
    "yanked_severity": "warning",
    "unsatisfiable_severity": "warning",
    "deprecated_severity": "warning",
    "mutable_ref_pin_severity": "hint",
    "mutable_ref_pin_enabled": true,
    "vulnerabilities_enabled": true
  },
  "freshness": {
    "enabled": true,
    "cooldown_secs": 259200
  },
  "cache": {
    "enabled": true,
    "fetch_timeout_secs": 5,
    "max_concurrent_fetches": 20
  },
  "loading_indicator": {
    "enabled": true,
    "fallback_to_hints": true,
    "loading_text": "..."
  },
  "cold_start": {
    "enabled": true,
    "rate_limit_ms": 100
  },
  "code_lens": {
    "enabled": true
  },
  "registries": {
    "workspace_registries": "public_only",
    "nuget_user_profile_sources": false,
    "gitlab_instance_host": ""
  },
  "network": {
    "offline": false
  },
  "supply_chain": {
    "enabled": true
  },
  "license_policy": {
    "allow": [],
    "deny": []
  },
  "typosquat": {
    "enabled": false
  },
  "gossip": {
    "enabled": false
  }
}
```

## Notes and Caveats

> **Note:** `diagnostics.outdated_severity`, `diagnostics.unknown_severity`,
> `diagnostics.unsatisfiable_severity`, and `diagnostics.yanked_severity` are all honored
> end-to-end. The yanked diagnostic fires in two independent cases (never both at once for the
> same dependency): (1) the dependency's in-use version — lock-file-resolved, or an exact pin such
> as `requirements.txt`'s `==1.2.3` — is itself reported as yanked/deprecated/retracted, supported
> for **Cargo, npm, PyPI, Bundler, and Dart**; or (2) the dependency's declared version
> *requirement* (a range) is currently satisfiable only by yanked versions, even with no lock file
> at all. See [Yanked Version Diagnostic](cross-ecosystem/yanked-and-vulnerabilities.md#yanked-version-diagnostic)
> for exact semantics and per-ecosystem coverage of each case (RubyGems cannot be detected by
> either mechanism, since its registry omits yanked versions from the list entirely rather than
> flagging them).

> **Note:** `diagnostics.deprecated_severity` flags a dependency whose *package* — not a specific
> version — is reported as deprecated/abandoned (`This package is deprecated: <reason>`), with a
> matching hover section and, for Composer packages naming a successor, a "Replace with X" quick
> fix. Currently sourced from **npm**'s `deprecated` field and **Composer**'s `abandoned` field
> only. See [Package Deprecation Diagnostics](cross-ecosystem/version-diagnostics.md#package-deprecation-diagnostics-issue-205)
> for the full ecosystem coverage table and how this differs from the yanked diagnostic above.

> **Note:** `diagnostics.mutable_ref_pin_severity` flags a **GitHub Actions or GitLab CI**
> dependency pinned to a mutable ref (a tag, e.g. `actions/checkout@v4`, or a GitLab `component:`
> pinned via `~latest`/a partial version) instead of a full commit SHA — a supply-chain hardening
> recommendation independent of the outdated-version check above (a dependency can be both up to
> date *and* mutable). Comes with a "Pin `<name>` to commit SHA" quick fix, and a bulk "Pin N
> {noun} to commit SHA" code lens batching every resolvable one in the document, when the commit
> SHA is already known (GitHub Actions rewrites the ref to `<sha> # <tag>`; GitLab CI rewrites to a
> bare `<sha>`). Set `diagnostics.mutable_ref_pin_enabled` to `false` to turn both the diagnostic
> and the bulk lens off entirely — unlike the other diagnostics above, severity alone cannot
> silence it. See [Mutable-Ref-Pin Diagnostic](cross-ecosystem/ci-pinning.md#mutable-ref-pin-diagnostic-issue-473-634)
> and [Bulk "Pin All to SHA" Code Lens](cross-ecosystem/ci-pinning.md#bulk-pin-all-to-sha-code-lens-issue-633-generalized-cross-ecosystem-in-640)
> for full details.

> **Note:** The release-freshness signal applies uniformly across all ecosystems — there is no
> per-ecosystem override. Coverage depth varies with what each registry exposes (e.g. Deno's
> `jsr:` specifiers get full coverage at no extra request cost; Swift, GitHub Actions, and
> Maven/Gradle have partial coverage since their APIs don't expose per-version publish dates
> directly). See [Swift/GitHub Actions Release-Freshness Coverage](ecosystems/swift.md#release-freshness-coverage-shared-with-github-actions)
> and [Maven/Gradle Release-Freshness Coverage](ecosystems/maven-gradle.md#release-freshness-coverage)
> for per-ecosystem details.

> **Note:** `network.offline` blocks every outbound request the server makes (registry, OSV
> vulnerability, and GitHub tags), across every ecosystem. Already-cached data keeps serving; an
> uncached dependency shows an offline marker in inlay hints, and hover appends a footer stating
> that version *and* vulnerability data were not checked. Toggling it via
> `workspace/didChangeConfiguration` takes effect immediately, with no editor restart.

> **Note:** The supply-chain trust signal only appears for **npm, Cargo, Go, Maven, PyPI,
> Bundler, and NuGet** (Composer, Dart, and Swift have no deps.dev coverage) and only for a
> dependency with a concrete in-use version — a lock-file-resolved version, or an exact
> requirement pin. It shows the linked source repository's OpenSSF Scorecard score and the
> resolved version's SLSA/attestation provenance status; a Scorecard fetched via a
> package-self-reported (rather than attested) repository link is marked `*(self-reported repo)*`.
> Informational only — a low score never becomes a diagnostic. See
> [Supply-Chain Trust Signal](cross-ecosystem/yanked-and-vulnerabilities.md#supply-chain-trust-signal-issue-543)
> for the full details.

> **Note:** `license_policy` diagnostics only fire for dependencies this feature already has
> license data for — **Composer, Dart, Swift, Deno, and Gradle**. This list is a snapshot, not a
> designed-in limit: any ecosystem whose registry client gains a `license:` field on its version
> type joins the diagnostic set automatically, with no further code changes required. Gradle's
> Maven Central POM licenses are free text (e.g. `"The Apache Software License, Version 2.0"`),
> not SPDX identifiers, so they are normalized against a known-variant table before evaluation —
> the table covers the common Apache/MIT/BSD/GPL/LGPL/AGPL/EPL/MPL/CDDL/ISC families but is not
> exhaustive. A free-text license the table doesn't recognize is never falsely flagged, but it is
> also **not enforced** — it is silently excluded from evaluation rather than guessed at, the same
> as a dependency with no license data at all. A dependency with no known license is never treated
> as a violation. `allow`/`deny` take exact, case-insensitive SPDX identifiers only — no
> `AND`/`OR`/`WITH` expression parsing. See
> [License Policy Diagnostic](cross-ecosystem/licensing.md#license-policy-diagnostic-issue-661)
> for matching rules and precedence.

> **Tip:** Increase `fetch_timeout_secs` for slower networks. The per-dependency timeout prevents
> slow packages from blocking others. Cold start support ensures LSP features work immediately
> when your IDE restores previously opened files.

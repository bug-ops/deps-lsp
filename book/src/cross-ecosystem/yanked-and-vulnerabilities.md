# Yanked Versions & Vulnerabilities

## Informational Advisories (issue #1043)

Not every OSV record is a graded vulnerability. `deps-lsp` classifies an OSV advisory as
`Informational` — instead of `Critical`/`High`/`Medium`/`Low`/`Unknown` — when its
`database_specific.informational` field is `"unmaintained"` on an entry that genuinely
describes the queried package (not a stranger sharing the same advisory id). This is an
**allowlist of exactly one value**: RUSTSEC's `"unsound"` (a real memory-safety/UB finding)
and `"notice"` (which can still describe a real defect) are deliberately *not* treated as
informational — an unrecognized or missing value falls through to the existing `Unknown`/
WARNING treatment rather than being silently downgraded to the less-visible informational
bucket.

An informational advisory renders distinctly rather than being hidden or conflated with a
real vulnerability:

- **Hover** labels it `maintenance-status notice, not a vulnerability` instead of a
  severity word, and a candidate version's "still vulnerable" line is suppressed only when
  *every* remaining advisory for it is known-informational — a mix of one informational and
  one graded advisory still shows the warning line.
- **Diagnostics** render at `INFORMATION` severity (not `WARNING`) and the message is
  prefixed `[INFORMATIONAL]`, so it is visually and severity-distinct from a graded
  advisory's diagnostic in the editor's Problems panel.
- A confirmed-malicious-package record (OSV's `MAL-` id prefix, e.g. via `aliases`) always
  takes precedence over an `informational` classification, even if the same record also
  carries `database_specific.informational: "unmaintained"`.

`deps-cli check`'s `vulnerable` category maps 1:1 to the same OSV scan `deps-lsp` runs, so
an informational-only advisory is reported the same way there — visible in the output, but
distinguishable from a graded finding via its severity field.

## Yanked-Version Diagnostics

`diagnostics.yanked_severity` flags a dependency pinned to a version the registry
reports as yanked/deprecated/retracted, covering either the lock-file-resolved
version or an exact manifest pin (e.g. `requirements.txt`'s `==1.2.3`) when no lock
file exists. Checked for every dependency with a known in-use version — not only
one that differs from the registry's reported latest — since it is a free
in-memory lookup against the version list `deps-lsp` already fetched to compute
"latest", and only against a registry that exposes real per-version yank data.

This is one of two independent yanked-related diagnostics; see
[Yanked Version Diagnostic](#yanked-version-diagnostic) below for the other, which
flags a *requirement* (a range, not necessarily an in-use version) satisfiable only
by yanked versions. `deps-lsp` never emits both for the same dependency — see that
section for how the two are deduplicated.

| Ecosystem | Yanked diagnostic | Registry signal |
|-----------|--------------------|------------------|
| Cargo | Yes | crates.io sparse-index `yanked` |
| npm | Yes | npm `deprecated` |
| PyPI | Yes | PEP 592 per-file yank status |
| Bundler | Yes | RubyGems `yanked` |
| Dart | Yes | pub.dev `retracted` |
| Go | No | module proxy reports no retraction data |
| Maven | No | Maven Central has no retraction concept |
| Gradle | No | delegates to the same Maven Central registry as Maven |
| Swift | Partial | SE-0292 registry releases carrying a `problem` are yanked; GitHub-tag dependencies have no yank signal |
| NuGet | No | unlisted versions are not distinguishable from listed ones today |
| Composer | No | Packagist's `abandoned` flag is package-level, not per-version — enabling it would fire on nearly every dependency of an abandoned package rather than the specific withdrawn release |
| Deno | Yes | JSR `meta.json` per-version `yanked` (genuine) for `jsr:` specifiers; npm `deprecated` (same package-level caveat as the npm row above) for `npm:` specifiers |

## Yanked Version Diagnostic

The other of the two independent yanked-related diagnostics — see
[Yanked-Version Diagnostics](#yanked-version-diagnostics) above for the in-use-version
check. When a dependency's declared version requirement is satisfiable, but **every**
version that satisfies it has been yanked/deprecated by the registry, deps-lsp shows a
WARNING diagnostic (configurable via `diagnostics.yanked_severity`):

```
This version has been yanked
```

This only fires when at least one matching version exists and all matching versions are
yanked — the same scan `Unsatisfiable Version Requirement` (see
[Version Diagnostics](version-diagnostics.md)) uses (via
`EcosystemFormatter::compile_bounded_requirement`), cross-referenced against the registry's yanked
flags. It is mutually exclusive with both the unsatisfiable WARNING (a yanked-only match is
a satisfied match, not zero matches) and the outdated/up-to-date check. If a non-yanked
version also satisfies the requirement (e.g. `^1.0` matching both a yanked `1.0.0` and a
non-yanked `1.0.1`), this diagnostic does not fire — the dependency is not actually stuck on
a yanked version, and the ordinary outdated/up-to-date check applies instead.

It is also mutually exclusive with the in-use-version [Yanked-Version
Diagnostics](#yanked-version-diagnostics) check above: for a dependency pinned to the one
version that also happens to be the only version satisfying its own requirement, both checks
would independently find a yanked verdict, but `generate_diagnostics_from_cache` skips this
check once the in-use-version check has already emitted a diagnostic for the same
dependency, so only one yanked diagnostic is ever shown per dependency.

- **npm is disabled entirely; Composer is restricted to exact-pin requirements.** Both source
  their yanked flag from a package-wide signal — npm's from `deprecated` (live-verified: the
  `request` package has 126/126 versions marked deprecated), Composer's from `abandoned` — not
  a true per-version yank, which is why this is a distinct diagnostic from [Package
  Deprecation Diagnostics](version-diagnostics.md#package-deprecation-diagnostics-issue-205) below
  rather than the same one. For npm, evaluating *any* requirement shape against that
  package-wide signal — including a bare exact pin — would too often just duplicate the
  package-level deprecation diagnostic, so this check is unconditionally off for npm (resolves
  #436); this also covers Deno's `npm:` specifiers, which delegate to npm's own registry data
  (resolves #448). For Composer, evaluating a range requirement against it would flag every
  dependency on an abandoned package, so a bare exact pin (`"1.2.3"`, not `"^1.2.3"`) is
  unaffected by that ambiguity and the check still applies there. Deno's `jsr:` specifiers are
  unrestricted (any requirement shape): JSR's `meta.json` `yanked` flag is a true per-version
  signal with no package-level deprecation payload to conflate with, unlike npm/Composer above
  (resolves #454).

**Ecosystem coverage, live-verified per registry rather than assumed from code:**

| Ecosystem | Works today? | Source |
| --------- | ------------- | ------ |
| Cargo | Yes | sparse index `yanked` field |
| npm | No | `deprecated` exists but the check is unconditionally off (see restriction above) |
| PyPI | Yes | PEP 592 `yanked` |
| Composer | Yes, exact pins only | `abandoned` (see restriction above) |
| Dart | Yes | pub.dev `retracted` |
| Bundler | No | RubyGems' `versions.json` never includes a `yanked` field on any entry (live-verified against the API directly) — indistinguishable from a version that never existed, same limitation the `Unsatisfiable Version Requirement` check documents |
| Go | No | `GoVersion.retracted` is hardcoded `false` at both construction sites in `deps-go`'s registry client — the field exists but is never populated from real data (tracked separately) |
| Maven | No | `MavenVersion::is_yanked` is a hardcoded `false` constant — Maven Central does not support version retraction |
| Gradle | No | reuses Maven Central's registry client, same hardcoded `false` |
| NuGet | No | `NuGetVersion::is_yanked` is a hardcoded `false` constant |
| Swift | Partial | `SwiftVersion.yanked` is `true` for an SE-0292 registry release with a `problem`, always `false` for GitHub tags (no such concept in the source); `SwiftRegistry::reports_yanked` is `true` |
| Deno | `jsr:` yes, any requirement shape; `npm:` no | JSR `meta.json` per-version `yanked` for `jsr:` specifiers; npm `deprecated` (unconditionally off, see restriction above) for `npm:` specifiers |
| GitHub Actions | No | GitHub's tags API exposes no yank/deprecation signal for actions — `GithubActionsRegistry::reports_yanked` is hardcoded `false`, same architectural gap as Swift |

5 of 13 ecosystems can produce this diagnostic today; npm is disabled by design rather than
lacking a real signal (see restriction above), and that also covers Deno's `npm:` specifiers;
the remaining 7 have no real yanked signal to source it from (four are architecturally
impossible — no such registry concept exists — and Go's is a fixable but separate gap).

## Latest-Version Safety Check (issue #1517)

`deps-lsp` and `deps-cli update` never recommend or apply a dependency's `latest` version
without an independent OSV.dev check on that exact version — not just on the version
currently pinned in the manifest. Before this fix, OSV's second-phase ("phase B") check on an
upgrade candidate only ran for a dependency **already** flagged vulnerable at its pinned
version, so a cleanly-pinned dependency's `latest` was never itself checked: every renderer
that recommends `latest` as an upgrade, and `deps-cli update`'s default mode, could recommend
or silently apply a version OSV.dev flags as malicious or critical. Phase B now runs for
**every** dependency whose registry-reported `latest` differs from its pinned/in-use version,
regardless of whether the pinned version itself has any advisories.

This is entirely ecosystem-agnostic: the check lives in `deps-core` (`osv::LatestStatusMap`,
`lsp_helpers::latest_verdict`), not in any one ecosystem crate, so it applies uniformly to
every ecosystem OSV.dev has an advisory feed for — there is no npm-specific or Cargo-specific
variant of this logic.

### The four verdicts

Every renderer computes one of four verdicts for the version it is about to show as `latest`,
via the shared `latest_verdict` gate:

- **Verified** — OSV.dev checked this exact version and found it clean (or affected only by an
  [informational](#informational-advisories-issue-1043) advisory). Shown normally as an
  ordinary upgrade recommendation.
- **Flagged** — OSV.dev checked this exact version and found a real advisory against it.
  Hover shows `🚫 Latest version is confirmed malicious by OSV.dev — do not upgrade to this
  version` (a confirmed-malicious-package record) or `⚠️ Latest version is flagged by OSV.dev
  — do not upgrade to this version` (any other non-informational advisory), and the advisory
  ids are listed. Diagnostics report `Latest version <v> is flagged by OSV (<ids>) — do not
  upgrade`, at `Error` severity for a malicious record or `Warning` otherwise (escalated above
  the configured `outdated` severity). Inlay hints show `🚫`/`⚠️ <v> flagged` instead of the
  plain outdated icon.
- **Unverified** — the version was never definitively checked: OSV hasn't completed phase B
  yet, a transient failure or timeout occurred, or the checked version has since diverged from
  what's now cached as `latest`. Diagnostics report `Newer version available: <v> (not yet
  verified against OSV)` at the ordinary `outdated` severity — visually distinct from both
  `Verified` (no such caveat) and `Flagged` (no escalated severity), but treated identically to
  `Flagged` for *whether the upgrade is recommended*.
- **NotApplicable** — OSV checking does not apply here at all: OSV is disabled or offline for
  this scan, or the dependency's source is structurally never checked against OSV (e.g. a git
  dependency, or an ecosystem OSV.dev does not cover). Renders exactly like `Verified` — no
  caveat, since there was never a check to distrust.

**The safety principle is fail-closed**: only `Verified` and `NotApplicable` are ever treated
as "safe to recommend or apply." Anything not affirmatively verified clean — including a
timeout, incomplete advisory data, or a deliberate offline/disabled skip — is treated the same
as an actively flagged version. This applies before the very first phase B run completes, too:
an empty status map (nothing checked yet) yields `Unverified`, never a silent pass-through.

### Where this applies

Every renderer that can surface `latest` as an upgrade consults this gate: hover, diagnostics,
code actions, code lens, inlay hints, and completion.

- The **"Fix Vulnerability" / "update to version X" code actions** (see below) and **completion's
  version items** never offer an item — `latest` or otherwise (issue #1524) — unless its own
  verdict is `Verified` or `NotApplicable`; a `Flagged` or `Unverified` item is simply omitted
  (code actions) or demoted/tagged (completion) rather than offered with no warning, so it can
  never be applied with one click.
- **`deps-cli update`'s default mode** refuses to write a `Flagged` or `Unverified` `latest`
  into the manifest at all — the dependency is reported as `Unplannable` with reason
  `LatestFlaggedByOsv` or `LatestUnverified` rather than silently dropped or silently applied.
  There is currently no override flag: a dependency in this state cannot be updated to `latest`
  via `deps-cli update` until OSV affirmatively clears it. If any in-scope dependency's `latest`
  comes back `Unverified` (rather than `Flagged`), the whole run aborts early with a clear
  message instead of silently omitting just that dependency, the same way a registry-unreachable
  condition does.
- As a side effect, a `Flagged` latest also suppresses the release-freshness/cooldown callout
  (hover's "recently published" notice and the equivalent GOSSIP-sourced diagnostic wording) for
  that version — a confirmed-unsafe version must never also read as a benign "just released,
  wait it out" notice.

### Non-latest candidate versions (issue #1524)

Phase B's candidate check also runs a bounded set of "candidate-check rounds" (up to 6, one per
rank among each dependency's newest non-yanked registry versions), independent of the single
`latest` check above, and stores each version's own verdict in `osv::CandidateStatusMap` —
looked up via `lsp_helpers::candidate_verdict`, the sibling of `latest_verdict` for a version
that isn't necessarily `latest`. Code actions' REFACTOR "update to X" list and completion's
version items both consult it for every item except the one identified as `latest` (which still
goes through `latest_verdict`/`LatestStatusMap`), so a non-latest intermediate version that was
never independently checked is demoted/excluded exactly like an unsafe `latest` already is.

The candidate-check rounds select the newest non-yanked entries from the registry's plain
version list (not the richer, `dyn Version`-based selection code actions/completion use to
choose what to *display*), so a display item outside that bounded set reads as `Unverified` and
is excluded/demoted; this is a deliberate over-conservative gap, never an under-conservative
one. In practice this is rare for **code actions** (they display the same unfiltered top
non-yanked set the rounds check), but **not** rare for **completion**: typing an
older-line prefix (e.g. `serde = "0.9.`) filters the display list down to versions the rounds
never cover at all, so every one of them reads as `Unverified` rather than transiently so.
Completion's rendering accounts for this — an `Unverified` item is demoted (sort order,
explanatory `detail` text) but not tagged `DEPRECATED` (no strikethrough), since that would
otherwise read as "OSV actively flagged this" rather than "not independently checked."

Completion's own gate for whether to run this check *at all* is `CompletionOrigin::Version` —
the typed signal `Ecosystem::generate_completions` already resolved — not a position-based
heuristic. PyPI's and Composer's `is_position_on_dependency` overrides widen the span they
consider "on this dependency" to include the package-name position too (PyPI extras
completion, Composer's alias forms), so using it as the sole gate would also reach
package-name completion on those two ecosystems and demote every item on every keystroke while
vulnerabilities checking is enabled.

Once a version-completion context is confirmed, locating *which* dependency is being completed
uses `completion::version_dependency_at_position` — the same two-pass lookup
(`version_range`-based, falling back to a same-line candidate when `version_range` is absent or
the cursor sits just outside it) an ecosystem's own version-completion dispatch already applies
to produce the completion items in the first place — not `is_position_on_dependency`, whose
default has no such fallback and live-verified misses Maven's self-closing `<version/>` tag (no
version text to have a `version_range` over). A lookup miss past this point — which shouldn't
happen once the context is confirmed, but the document can still have changed between the
request and this check — fails closed: every item is marked unverified rather than left
untouched.

### Requirement admits a flagged `latest` (issue #1526)

A permissive semver range can admit the registry's `latest` without the dependency ever reading
as `Outdated` (e.g. `^1.0.4` with no lock file, where `1.0.4` is itself the flagged version) —
`requirement_status_for` returns `RequirementStatus::UpToDate` in this case, not `Outdated`. The
outdated-diagnostic rule and the up-to-date inlay-hint rendering both now consult
`latest_verdict` in this branch too, surfacing a diagnostic/warning icon when it resolves to
`Flagged`, instead of silently returning as if there were nothing to report. Deliberately scoped
to `Flagged` only, not `Unverified`: `Unverified` is the common, transient state for every
dependency before phase B first completes, and introducing a brand-new diagnostic on every
up-to-date dependency during that window would be a broad noise regression neither surface had
before.

## Code Action: Fix Vulnerability

A dependency flagged by the OSV vulnerability scan (see the security-advisories hover
section and diagnostics) gets an extra code action alongside the plain "update to
version X" list: a quickfix titled `Update to <version> (fixes <ADVISORY-ID>[ +N more])`,
naming only the worst-severity advisory id and summarizing the rest so the title stays
readable in an editor's code-action menu (the full id list still travels with the action
so editors can bind it to the matching diagnostics — see below). The target version is the
*lowest* version that resolves every advisory the action claims to fix: an advisory OSV
reports as still applying at the checked candidate (from the scan's second-phase check) is
excluded from the claim, and — crucially — excluded *before* the target version is picked,
so that advisory's own fix version (which may be much higher) can never inflate the
recommendation past what the claimed advisories actually need.

The action is independent of the registry fetch that produces the plain update list, so a
registry outage never hides it. When the registry fetch does succeed, a fix version the
registry reports as yanked is dropped instead of offered (no action, rather than silently
retargeting to some other version), and a fix version whose *formatted* manifest text
already matches the dependency's declared requirement is skipped as a no-op edit — the
comparison uses the actual text the edit would write, not the bare version, since several
ecosystems format it differently (Dart wraps it in a `^` constraint, PyPI expands it into a
`>=,<` range). If the scanned version came from the lock file rather than the declared
requirement, the title gets an `; update lockfile to apply` suffix, since editing the
manifest alone will not clear the diagnostic until the lock file is regenerated.

Editors that support diagnostic-bound quickfixes (surfacing the action from the advisory's
own lightbulb rather than only the generic code-action menu) get this automatically: the
action carries its resolved advisory ids internally, and `deps-lsp` binds it to any
matching diagnostic the client already reported for the same range. Filtering code actions
by kind (e.g. an editor's "quick fix only" view) is also honored.

**Go note.** The formatter hook this action relies on to convert an OSV-reported version
into `go.mod`'s `v`-prefixed form is in place, but Go's vulnerability scan currently sends
the `v`-prefixed module version to OSV, which expects it unprefixed, and gets no matches
back (tracked separately) — so no Go dependency can trigger this action yet.

## Supply-Chain Trust Signal (issue #543)

Hover can show an additional, informational line for a dependency's upstream supply-chain
health, sourced from [deps.dev API v3](https://docs.deps.dev/api/v3/) — a free, keyless,
cross-ecosystem metadata API. Two independent pieces of data are shown together on one line:

```
🔐 Supply chain: OpenSSF Scorecard `8.5`/10 · Provenance: verified
```

- **OpenSSF Scorecard** — the linked source repository's aggregate score (0-10), from checks
  like Code-Review, Dangerous-Workflow, Maintained, and Branch-Protection.
- **Build provenance** — whether the *specific resolved version* has a verified build
  provenance or attestation: `verified` (at least one `slsaProvenances[]`/`attestations[]`
  entry is verified), `attested but unverified` (an entry exists but none is verified — shown
  rather than silently omitted, so "we checked and found nothing" is never confused with "we
  didn't check"), or `none found` (no provenance data at all for this version). Labeled plainly
  as "Provenance", not "SLSA provenance": the two arrays are unioned, and an `attestations[]`
  entry is not necessarily SLSA-specific.

Both halves render independently — a package with a Scorecard but no provenance data (or vice
versa) shows only the half that resolved. The section is omitted entirely, with no error or
warning, whenever deps.dev has nothing to offer: an unsupported ecosystem, no linked source
repository, a deps.dev outage, or no concrete in-use version for the dependency (a lock-file-
resolved version, or an exact requirement pin — the provenance claim is version-specific, so no
in-use version means nothing safe to query).

**Self-reported repository disclosure.** A package can carry several `SOURCE_REPO` links to
deps.dev, distinguished by whether the link is `SLSA_ATTESTATION`-backed (cryptographically
tied to the published artifact) or merely `UNVERIFIED_METADATA` (taken from the package's own,
unverified manifest metadata). `deps-lsp` prefers the attested link; when only a self-reported
one exists, the score is still shown but marked `*(self-reported repo)*` — a package could
otherwise point its metadata at an unrelated, reputable repository and borrow its Scorecard.

**Coverage.** deps.dev covers **npm, Cargo, Go, Maven, PyPI, Bundler, and NuGet** — Composer,
Dart, and Swift have no deps.dev coverage and issue zero requests for this signal. Gradle and
Deno's `npm:` specifiers are not covered by this iteration either, though deps.dev's `maven`
system would cover Gradle coordinates without further mapping work.

**Performance.** The fetch runs as a detached background task alongside the dependency's normal
registry fetch, bounded by a short wait budget on the hover response itself — a slow or
first-ever (cold-cache) deps.dev lookup never delays or blocks any other hover content, and an
over-budget fetch still finishes into an in-process cache so the *next* hover on that dependency
is instant. Set `supply_chain.enabled` to `false` to turn the signal (and every deps.dev
request) off entirely — see the
[Configuration reference](../configuration.md#configuration-reference).

Informational only, permanently: a low Scorecard score never becomes a diagnostic, warning, or
blocking behavior, matching the release-freshness signal's precedent for a
supply-chain-risk-adjacent hover addition.

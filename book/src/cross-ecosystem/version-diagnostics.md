# Version Diagnostics

## Unsatisfiable Version Requirement

When a dependency's declared version requirement matches **zero published versions** — of
any kind, stable, prerelease, or yanked — deps-lsp shows a WARNING diagnostic:

```
No published version satisfies requirement '99'; latest is 1.0.214
```

This is distinct from `Unknown package` (the package itself was not found) and from the
"Newer version available" HINT (a satisfiable requirement that simply isn't pinned to the
latest release). The two are mutually exclusive on the same dependency — a requirement is
either up to date, outdated-but-satisfiable, or unsatisfiable, never more than one at once.

The check is always on (no configuration flag) across 12 of the 13 ecosystems — GitHub
Actions does not opt in (a pin is not a range, so there is no "requirement satisfies zero
versions" question to ask) — and is deliberately conservative:

- **Suppressed while versions are still loading**, or if the registry fetch failed — an
  empty/unknown version list means "don't know yet", not "nothing published".
- **Suppressed for path/git/URL/SDK/workspace dependencies** — their `version` field, if
  present, does not refer to something resolvable against the ecosystem's package registry
  at all (e.g. this project's own `deps-core = { path = ..., version = "0.10.1" }`, or
  Dart's `{ sdk: flutter, version: "^3.24.0" }`, which resolves against pub.dev's unrelated
  package literally named `flutter`).
- **Suppressed for an unresolved requirement** — a dangling Gradle version-catalog
  `version.ref` alias or an unexpanded Maven `${property}` was never actually checked
  against anything.
- **A prerelease-only or yanked-only match still counts as satisfied** — neither triggers
  this WARNING. `foo = "2.0.0-beta.1"` is a deliberate opt-in, and a yanked version is still
  installable when pinned (Cargo resolves yanked versions present in the lock file); flagging
  either as unsatisfiable would be a false positive. A yanked-only match is not silent,
  though — it surfaces instead as the separate
  [Yanked Version Diagnostic](yanked-and-vulnerabilities.md#yanked-version-diagnostic).
- **Suppressed for requirement forms naming a version outside the fetched candidate list by
  construction**, not just failing to match one present in it — Go pseudo-versions and
  `dev-*`/`*-dev`/`@dev` Composer branches (never enumerable from the registry list at all),
  and Maven/Gradle `-SNAPSHOT`/`LATEST`/`RELEASE` (resolved via a different repository/side
  channel this registry never queries).
- **RubyGems exact pins are suppressed only when the pin does not exceed the highest
  published version.** RubyGems' `versions.json` omits yanked versions from the list with no
  flag to detect them, so a pin that could plausibly name a hidden yanked version is not
  flagged. A pin above every published version — a mistyped or genuinely unpublished version,
  e.g. `gem "foo", "99.0.0"` when `foo` tops out at `2.0` — is still flagged as unsatisfiable.
- Each ecosystem opts in by implementing a precise per-version-format comparator (the same
  crate its registry client already depends on: `semver` for Cargo/Swift, `node-semver` for
  npm, `pep440_rs` for PyPI, bracket-interval range parsers for Maven/Gradle/NuGet, and
  exact/pattern comparators for Go/Bundler/Dart/Composer) — not the same loose heuristic
  used for the "up to date" hint, which is intentionally permissive and would produce false
  positives if reused here (e.g. Cargo's `~1.0.999` reads as "up to date" against a latest
  of `1.0.214` under the loose same-major-minor heuristic, despite patch `999` never having
  been published).
- **Cargo, npm, and Swift additionally name a matching pre-release, if one exists.** These
  three ecosystems use a strict SemVer-style matcher that excludes prereleases unless the
  requirement itself names one — so a requirement like `^2.0.0` reads as fully unsatisfiable
  even when a `2.0.0-rc.1` has been published. The WARNING then appends a clause naming it:
  ```
  No published version satisfies requirement '^2.0.0'; latest is 1.5.0 (a pre-release,
  2.0.0-rc.1, is excluded by SemVer's default pre-release-matching rules; require it
  explicitly to use it)
  ```
  The hint is skipped when the requirement itself already names a pre-release (the real
  blocker there is version ordering, not pre-release exclusion) and when the only matching
  pre-release has been yanked. Maven/NuGet/Composer/Gradle's range-parsing model already
  admits prerelease qualifiers within a range and is unaffected.

**Not yet implemented:** a separate informational diagnostic for a requirement that only
matches prerelease versions.

## Code Action: Fix Unsatisfiable Requirement

A dependency flagged by the diagnostic above gets a `QUICKFIX` titled `Fix unsatisfiable
requirement: update to <version>`, targeting the same cached `latest` value the diagnostic
message names, so the action's title and the diagnostic text always agree on what "the
latest" is. The action is gated by the identical unsatisfiability check the diagnostic uses,
so the action never appears without the diagnostic — though several further guards (a
yanked target, a no-op or still-unsatisfiable rewrite, a text collision with the
vulnerability fix) can independently suppress the action while the diagnostic itself stays up.

Like the vulnerability fix above, this action is computed before the registry fetch that
produces the plain update list, so a registry outage never hides it. When the fetch does
succeed, a target the registry reports as yanked is dropped rather than offered. The
rewritten text is re-checked against the same unsatisfiability predicate before the action
is returned, since an ecosystem that preserves operator style when rewriting a requirement
(PyPI, Gradle) can otherwise produce another still-unsatisfiable range; this re-check cannot
prove a rewrite it cannot evaluate is correct, so it holds for every rewrite the ecosystem's
own comparator can judge, not unconditionally.

If both this action and the vulnerability fix apply to the same dependency and would write
byte-identical text, the vulnerability fix (the more informative title) is kept and this one
is dropped. At most one action across the whole response is ever marked as the editor's
preferred quickfix, in priority order: vulnerability fix, then unsatisfiable-requirement fix,
then the REFACTOR item pointing at the newest available version.

Editors that support diagnostic-bound quickfixes get this automatically, the same way as the
vulnerability fix ([Code Action: Fix Vulnerability](yanked-and-vulnerabilities.md#code-action-fix-vulnerability)):
the action binds to any matching diagnostic the client already reported for an overlapping
range.

## Package Deprecation Diagnostics (issue #205)

The two yanked diagnostics above (see [Yanked Versions &
Vulnerabilities](yanked-and-vulnerabilities.md)) answer "is *this version* installable"; this
one answers a different, package-level question — "is the project itself still maintained" —
regardless of which version is declared or resolved. When the registry reports the package's
latest version as deprecated/abandoned, `deps-lsp` shows a diagnostic (configurable via
`diagnostics.deprecated_severity`, default WARNING):

```
This package is deprecated: use String.prototype.padStart() instead
```

The hover popup gets a matching `### Deprecated` section with the same reason text and, when
the registry names one, a suggested replacement package. Derived entirely from data the
regular version fetch already retrieves — no extra registry request.

**Suppression against the yanked diagnostics above.** npm's yanked signal is itself sourced
from the same `deprecated` field this diagnostic reads, so a dependency pinned to an exact,
deprecated version would otherwise show two near-duplicate diagnostics. When this diagnostic
fires, it suppresses *both* yanked checks above for the same dependency — the in-use-version
check and the range-requirement-only-satisfiable-by-a-flagged-version check — but only when
the matched yanked finding's underlying signal is an advisory (`AdvisoryDeprecated`), never a
genuine hard yank/retraction. A package that is both deprecated *and* has a specific version
really withdrawn from resolution still shows both diagnostics; "the exact version you have was
pulled" is strictly more actionable than "the project is archived," and one must never hide
the other.

Each of the two yanked checks decides this independently from its own matched version's
`RemovalStatus` (issue #437) — the range check does not defer to, or require, the
in-use-version check's own finding. This matters once an ecosystem's per-version status can be
`AdvisoryDeprecated` for one version and `Yanked` for another within the same package (not
possible for npm/Composer today, since npm never reports a real yank and Composer's range
check never runs, but expected once PyPI's PEP 592 yanks and PEP 792 `project-status` coexist):
a range requirement satisfiable only by a genuinely yanked version still fires even when the
package's separately-tracked in-use/latest version is merely deprecated and its own diagnostic
was suppressed.

**Composer-only "Replace with X" code action.** When Packagist's `abandoned` field names a
successor package, a `QUICKFIX` titled `Replace with <package>` rewrites the dependency's name
in place. Not offered for npm: its only successor signal is free-text prose inside the
`deprecated` message, and regex-extracting a package name from registry-controlled text to
rewrite a manifest is a typosquatting vector — npm still gets the diagnostic and hover (the
message is shown verbatim, which is the useful part), just not an automated rename.

| Ecosystem | Works today? | Source |
| --------- | ------------- | ------ |
| npm | Yes | `deprecated` free-text message (no structured replacement — see above) |
| Composer | Yes, with replace action | `abandoned` (bare `true`, or a string naming a successor package) |
| Cargo, Go, PyPI, Bundler, Dart, Maven, Gradle, Swift, NuGet, Deno | Not yet | No registry-native package-level deprecation signal wired up yet (tracked as fast-follows; Dart's `isDiscontinued`/`replacedBy` and PyPI's PEP 792 `project-status` already exist on the wire and are the best next targets) |

## Dependency-Count Ceiling Diagnostic (issue #796)

**All 14 ecosystems.** A manifest may declare far more dependency entries than any real
project has — an adversarial or malformed file with hundreds of thousands of declarations
would otherwise drive both server memory and outbound registry request volume linearly with
a number the manifest's author controls. Each ecosystem's own parser threads a shared
`deps_core::DependencyBudget` through its dependency-collecting loop(s), so the concrete
per-document dependency list it retains — the thing that stays resident in memory for the
life of the open document — never grows past `MAX_DEPENDENCIES_PER_DOCUMENT` (5000) in the
first place, rather than being truncated after an oversized list was already built and kept
around. `deps_core::ecosystem::parse_manifest_blocking` (the single chokepoint every
ecosystem's parse result flows through before reaching `deps-lsp`) applies
`deps_core::dependency_cap`'s view-level cap as a belt-and-braces backstop on top, so hover,
completion, diagnostics, inlay hints, code lens, and the registry fetch fan-out all only
ever see the capped subset even if some ecosystem parser were ever added without wiring in
the budget itself. The largest real-world manifests sit in the low hundreds of dependencies,
so this leaves generous headroom for any legitimate project.

When a manifest exceeds the ceiling, only the first 5000 declared dependencies are tracked
and checked against the registry; the rest are silently untracked (parsing itself is not
rejected, unlike the unrelated 10MB file-size limit). An `INFORMATION`-severity diagnostic
is published at the top of the file naming the limit and the manifest's true dependency
count:

```
manifest declares 12000 dependencies, exceeding deps-lsp's per-document limit of 5000; only the first 5000 are tracked, fetched, and checked against the registry
```

This limit is hardcoded, not configurable — the same "security limit, not a user
preference" reasoning as the 10MB file-size cap.

## CodeLens: "Update N Outdated Dependencies"

An open manifest with at least one outdated, safely-editable dependency shows a code lens at
the top of the document, titled `Update N outdated dependencies`. Clicking it applies a
single batch edit that rewrites every such dependency's version to the latest known
version, sharing the same "is this outdated" definition as diagnostics (a requirement
already satisfied by the latest version — e.g. Cargo's `^1.2` accepting `1.9` — is left
alone; that lag is the lock file's, not the manifest's, to fix).

**Coverage caveat.** Before rewriting a dependency's declared version text, the feature
verifies the manifest span it is about to edit actually *is* that version literal. Some
ecosystems point the tracked span at something else instead:

- **`pom.xml`** dependencies versioned through a `<properties>` placeholder (`<version>${my.version}</version>`) are skipped — the span covers the placeholder, not a literal.
- **Gradle** dependencies versioned through a DSL variable (`"...:$myVersion"`, resolved from `gradle.properties`) or a `libs.versions.toml` version-catalog alias (`version.ref = "spring"`) are skipped for the same reason.
- **`Package.swift`** dependencies declared with a two-literal range (`"1.0.0"..<"2.0.0"` or `"1.0.0"..."1.9.9"`) are skipped — the tracked span covers only the range's lower-bound literal, and rewriting that literal alone would invert the range (SwiftPM traps on `lowerBound > upperBound`, corrupting the whole manifest) rather than leave a merely-stale-but-valid declaration.

For these, no lens appears even when the dependency is genuinely outdated — this is the
correct, conservative behavior (silently declining to edit is far better than corrupting a
build file), not a bug. The per-line "Update to latest version" code action shares the exact
same guard, so it declines the same way rather than corrupting these declarations.

`Package.swift`'s other declaration forms (`from:`, `.upToNextMajor`, `.upToNextMinor`,
`.exact`) were affected by this same guard through #367: each synthesizes a comparator
requirement (e.g. `.exact("4.50.0")` -> `=4.50.0`) that never textually matched the bare
version literal the tracked span actually points at, so the guard rejected every one of
them and both the lens and the code action silently did nothing. Fixed by having
`deps-swift` additionally report the bare literal (`Dependency::version_literal()`) the
guard should compare against; these four forms now get a lens and code actions like any
other registry-form dependency (`.branch`/`.revision`/`.package(path:)` dependencies still
have no version to update, same as any other ecosystem's git/path dependency, and the two
range forms above remain guard-skipped by design).

Only the six documented `.package(...)` spellings above are parsed at all — a handful of
other valid SwiftPM argument-label combinations (`.package(url:exact:)`, `.package(url:
branch:)`/`(url:revision:)`, `.package(id:...)`, the legacy `.package(name:url:...)`, or any
of the above with a trailing comma) currently parse to zero dependencies rather than a
skipped one; extending parser coverage to them is tracked separately, out of scope here.

**Known divergence from inlay hints (accepted, documented).** Inlay hints use a
lock-file-aware "outdated" check (resolved version vs. latest), while the lens and
diagnostics use the manifest-requirement check described above. With a lagging lock file
and a requirement permissive enough to already accept the latest version, inlay hints can
render `❌ <version>` on a dependency with no matching diagnostic and no lens — the fix
in that case is regenerating the lock file, which only the package manager can do, so
there is nothing for the lens to edit. Unifying the two definitions is tracked as a
follow-up.

# Licensing

## License Hover

Hover shows the SPDX license identifier(s) for the resolved version, and flags a
"License changed" warning when the latest version's license differs (issue #204).
Covered for Cargo, npm, PyPI, Go, Maven, Bundler, NuGet (via the deps.dev
supply-chain call — resolved version only, the "latest" license degrades to
"unavailable" since no second network call is made) and Composer (via Packagist's
own version list, which carries license for both the resolved and latest version,
enabling the "License changed" comparison). When license data is unavailable for
a dependency, the section is omitted rather than shown as "unknown".

Dart, Swift, Gradle, and Deno (issue #660) are covered via a per-ecosystem
background pre-fetch (mirroring the OSV vulnerability-scan pattern — never
blocking hover latency) instead of the deps.dev/Packagist hot-path call above.
This pre-fetch has its own **10-second timeout floor**, independent of a lower
configured [`fetch_timeout_secs`](../configuration.md#configuration-reference)
(which can be set as low as 1s): Gradle's `<parent>` POM traversal (below) may need up
to a few sequential HTTPS round trips for one dependency, so clamping the
pre-fetch's timeout down to a very low `fetch_timeout_secs` would silently
starve exactly the parent-chained licenses this feature exists to resolve
(issue #692 critic M2). A user tuning `fetch_timeout_secs` down for fast
feedback on the hot registry-fetch path is unaffected there — only this
background license pre-fetch keeps a higher floor.

| Ecosystem | Source | Renders as |
|-----------|--------|------------|
| Dart | pub.dev `/score` best-effort license *detector* tag, per-**package** (not per-version) | `**License (detected)**` |
| Swift | GitHub's `licensee`-detected `license.spdx_id` on the repository's default branch (not the resolved version's tag) | `**License (detected)**` |
| Gradle | Maven Central POM `<license><name>`, fetched for the resolved version — following the POM's `<parent>` coordinate (bounded to a few hops) when that POM declares no `<licenses>` block of its own (issue #692, e.g. Guava's license is declared only on `guava-parent`'s POM) | `**License**` |
| Deno | JSR's per-version `license` field (`jsr:` specifiers only) | `**License**` |

Which of these four "sources" a dependency's license is depends on the ecosystem
crate's `Ecosystem::license_source()` (issue #688/#697): `RegistryDeclaredSpdx`
(author-declared, arriving for free in the hot-path registry response — the
default, every ecosystem above except Dart/Swift/Gradle/Deno), `FetchedDeclaredSpdx`
(Deno only — author-declared, but via JSR's dedicated per-version fetch rather than
the hot-path response), `DetectedSpdx` (Dart/Swift — a best-effort *detector*, not
author-declared metadata, hence the `(detected)` qualifier), or `PomFreeText`
(Gradle only — Maven POM `<license><name>` free text, e.g. `"The Apache Software
License, Version 2.0"`, never an SPDX identifier). `LicenseSource::requires_dedicated_fetch()`
is `true` for every variant except `RegistryDeclaredSpdx` — this is also the single
gate `deps-lsp`'s tier-3 license pre-fetch uses to decide whether to call an
ecosystem's `fetch_license` at all. Gradle's free text is normalized once,
at the shared pre-fetch data boundary (issue #687), but hover and
[License Policy Diagnostic](#license-policy-diagnostic-issue-661) below use two
different views of that normalization
(`deps_core::licenses::resolve_license_entries_for_display` vs
`resolve_license_entries`), not identical output: hover renders a single
canonical id (`Apache-2.0`), while policy evaluation gets the full
SPDX-convention-ambiguous synonym slice a `deny`/`allow` list needs to match
against (the GPL family normalizes to three ids — see below) — printing all
three in hover would read as three licenses for what is genuinely one. A POM
name the normalization table doesn't recognize falls back to the raw text in
hover (never silently vanishes) but is dropped, not guessed at, for policy
evaluation. Dart/Swift have no license data at all without a resolved version
(`pubspec.lock`/`Package.resolved` — both endpoints require an in-use version
to look up, even though the data itself isn't version-specific).

## License Policy Diagnostic (issue #661)

Configuring `license_policy.allow`/`license_policy.deny` (see the
[Configuration reference](../configuration.md#configuration-reference))
produces a diagnostic for a dependency whose known license violates the policy, anchored at the
same manifest line as the outdated/vulnerability diagnostics. Both lists take exact,
case-insensitive SPDX identifiers only — no `AND`/`OR`/`WITH` expression-operator
parsing (spec 010 plan.md's explicit v1 scope decision); an invalid entry is
dropped with a logged warning at config-load time rather than rejecting the whole
`license_policy` payload.

- **Deny wins over allow** when a license matches both — mirrors `cargo deny
  licenses`' own precedence convention. Renders as an ERROR diagnostic.
- **Not on the allow-list** (a non-empty `allow` configured, and none of the
  dependency's declared licenses matches) renders as a WARNING diagnostic.
- **No known license** (the dependency isn't one of the ecosystems below, or its
  license hasn't been fetched yet) never violates the policy — there is nothing
  to check, not a hidden deny.
- **Multi-licensed dependencies** (more than one declared license): denied if
  *any* entry matches `deny` (errs toward flagging for manual review); allowed if
  *any* entry matches a non-empty `allow` (the permissive reading — the consumer
  can pick whichever license they comply with).

**Coverage is Composer, plus exactly the ecosystems [License Hover](#license-hover)'s
background pre-fetch covers — Dart, Swift, Deno, and Gradle.** Composer's license
arrives for free in its hot-path registry response (`RegistryDeclaredSpdx`, via
Packagist's own version list — see [License Hover](#license-hover) above), so it
needs no dedicated pre-fetch to populate the diagnostic's synchronous license map;
any other ecosystem whose registry client starts returning a `license:` field on
its version type joins this set the same way, with no further code changes. Gradle's
Maven Central POM licenses are free text (e.g. `"The Apache Software License,
Version 2.0"`), never SPDX identifiers, so directly matching them against an SPDX
allow/deny list would produce both false positives (a compliant `Apache-2.0`
dependency reported "not on the allowed license list") and false negatives (a
`GPL-3.0` deny-list entry never matching `"GNU General Public License v3"`).
`deps-core::licenses::normalize_pom_license_names` (issue #679) maps known Maven
Central POM free-text variants (Apache/MIT/BSD/GPL/LGPL/AGPL/EPL/MPL/CDDL/ISC)
to their canonical SPDX identifier(s) before evaluation — free text that never
disambiguates the deprecated bare id from the current `-only`/`-or-later` split
(e.g. `"GNU General Public License v3"`) normalizes to all three forms, so a
`deny`/`allow` list written in either convention still matches. If *any* of a
dependency's declared license entries fails to normalize, only a `NotAllowed`
conclusion is suppressed for it (the surviving evidence is incomplete, so
"nothing matched" can't be trusted); a `Denied` match on a normalized entry
still fires regardless. A Gradle license this table doesn't recognize is never
falsely flagged, but it is also **not enforced** — it is excluded from
evaluation rather than guessed at, the same as a dependency with no license
data. The table is not exhaustive; an unrecognized license on a `deny` list
silently escapes enforcement until that variant is added to
`KNOWN_POM_LICENSE_NAMES`. Hover and this diagnostic normalize through the same
data boundary but read two different views of it (see [License Hover](#license-hover)
above, issue #687): a recognized entry's diagnostic message shows the same
canonical id hover does (e.g. `Apache-2.0`), but an SPDX-convention-ambiguous
entry's message may list more ids than hover's single canonical one (the GPL
family's `GPL-3.0`, `GPL-3.0-only`, `GPL-3.0-or-later`) — that expansion is
policy-matching evidence, not something hover should also print. Either way,
neither surface ever shows the original free text for a recognized entry.

This diagnostic is evaluated identically whether it was triggered by a
`textDocument/diagnostic` pull request or a background push refresh (a
fetch-completion, watched-config, or lock-file-change reparse) — the currently
configured policy is cached server-side and kept live-updated by
`workspace/didChangeConfiguration`, so it never depends on which code path
happened to generate a given diagnostics response.

# Conventions

## Inlay Hint Icons at a Glance

Every ecosystem's "inlay hints" (the inline text shown right next to a dependency's
version in the manifest) come from the same four icons, all defined in `deps-core`'s
`Ecosystem` trait defaults and `deps-lsp`'s config:

| Icon | Meaning | Shown when |
|------|---------|------------|
| ✅ | Up to date | The declared version already matches the latest available version. |
| ❌ `<version>` | Update available | A newer version exists; `<version>` is the latest one, substituted into the hint text. |
| ⏳ | Loading | Version/vulnerability data is still being fetched from the registry. Only appears for editors that don't support LSP work-done progress reporting — most editors show a native progress indicator instead. |
| 📴 | Offline | Network access is disabled, so version and vulnerability data were not checked. Also appears as an "Offline: version and vulnerability data not checked" note in hover text. |

All four are user-configurable — an editor/client can override the up-to-date and
needs-update text via the `inlay_hints` LSP config block, and the loading text via
`loading_indicator`. The examples above are the defaults.

**✅/❌ compares against the lock file, not the manifest range, when a lock file
exists.** When a lock file (`Cargo.lock`, `package-lock.json`, etc.) is present, the
icon is decided by comparing the **lock-resolved version** against the latest
release — the manifest's version range is not consulted in that case. So a manifest
range that already covers the latest release (e.g. `Cargo.toml` declares `^2.0` and
the latest published version is `2.1.1`) can still show `❌` if the lock file hasn't
been regenerated and still resolves to an older version (e.g. `2.0.5`). The fix is to
update/regenerate the lock file, not necessarily the manifest range. The manifest
range is used directly only as a fallback, when no resolved lock version is
available. **Go is the exception**: it reads the resolved version from `go.mod`'s own
directive rather than from `go.sum`, because `go.sum` isn't a reliable source for the
in-use version — so for Go, the manifest drives the icon directly.

**Not every status gets an icon.** Yanked, deprecated, and unsatisfiable-requirement
dependencies, and OSV vulnerabilities, are surfaced as plain text in hover content (e.g.
`(yanked)`, `(deprecated)`, a CVE severity label) and as standard LSP diagnostics — the
squiggly underlines and problem-panel entries your editor already renders for warnings and
hints — rather than as an inlay-hint icon. If you don't see an icon for one of these, check
hover and the diagnostics panel instead.

## Hover, Diagnostic & Code Lens Text Conventions

Hover content is Markdown, built from the same handful of building blocks across
every ecosystem; diagnostics and code lens titles are plain text with no icon or
Markdown convention of their own.

| Convention | Example | Meaning |
|------|---------|------------|
| `**Label**: \`value\`` | `**Current**: \`1.2.0\``, `**Latest**: \`1.3.0\`` | Bold label plus a code span for a version/fact. The package name itself is an H1 heading, linked to the registry page when one is available. |
| `*(status)*` | `` `1.2.0` *(yanked)* `` | Yanked/deprecated status, always italicized in parentheses, shown next to the version in the "Recent versions" list. Most ecosystems say `*(deprecated)*`; Composer uses Packagist's own term, `*(abandoned)*`. |
| `> callout` | `> ⏳ **Recently published** — ...` | Markdown blockquote shown when a version is still inside the release-cooldown window. |
| `### Security advisories` | `- **[CVE-XXXX-YYYY](advisory link)** — critical` then a summary line and `Fixed in: \`1.2.4\`` | One bullet per advisory: linked CVE/GHSA id, plain-text severity (`critical`/`high`/`medium`/`low`/`unknown severity`/`confirmed malicious package`/`maintenance-status notice, not a vulnerability`), a summary line, and the fixed-in version. When a package has been scanned and has no advisories, hover shows `**No known vulnerabilities** (OSV.dev)` instead — this line only appears after a scan actually ran, never for an unscanned package. |
| unheaded line | `🔐 **Supply chain**: OpenSSF Scorecard \`7.5\`/10 · Provenance: verified` | OpenSSF Scorecard score and/or SLSA-provenance verdict (via deps.dev), on its own line with no heading. Omitted entirely when neither signal is available. |
| `---` + footer | `⌨️ **Press \`Cmd+.\` to update version**`, `📴 *Offline: version and vulnerability data not checked*` | Each footer is preceded by a Markdown horizontal rule. The first appears when a newer version is available; the second while `network.offline` is active. |

**Diagnostics and code lens are plain text, not Markdown, and have no icon
convention.** Diagnostic message wording is deliberately not unified across rule
types even for similar situations (for example, "yanked and currently in use" and
"yanked but only reachable through the declared range" use different phrasing) —
their visual severity (squiggly underline color, problem-panel icon) comes
entirely from the editor, driven by the `diagnostics` config block (HINT/WARNING
per rule), not from any icon deps-lsp draws itself. Code lens
titles follow the same plain-text rule: "Update 1 outdated dependency" / "Update
{n} outdated dependencies", and for GitHub Actions/GitLab CI, "Pin 1 {kind} to
commit SHA" / "Pin {n} {kind} to commit SHA" — no emoji, positioned on the
manifest's first line.

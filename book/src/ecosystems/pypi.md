# PyPI

`deps-pypi` provides LSP support for Python projects, covering both TOML-based manifests and
pip's line-oriented requirements-file format from one crate.

## Basics

| | |
|---|---|
| Manifest files | `pyproject.toml` (PEP 621, PEP 735, Poetry, PEP 517/518 `build-system.requires`); `requirements*.txt`, `*-requirements.txt`, `*.requirements.txt`, `constraints*.txt`; any `.txt` directly under a `requirements/` directory |
| Lock file (in-use version) | `poetry.lock` or `uv.lock` |
| Registry | PyPI — PEP 691 Simple API JSON (`pypi.org/simple/{package}/`) for version lookups, JSON API (`pypi.org/pypi/{package}/json`) for hover metadata |
| Version syntax | PEP 440 version specifiers, parsed via `pep440_rs`; full PEP 508 requirement strings (extras, environment markers) via `pep508_rs` |

```toml
[project]
dependencies = [
    "requests>=2.31,<3",
    "numpy>=1.24; python_version>='3.9'",
]
```

Hover shows the requirement's PEP 440 satisfaction against the latest PyPI release, extras
(`requests[socks]`), and — when present — the environment marker in a readable "Active when:"
form (see [Environment Markers](#environment-markers-pep-508) below). The same PEP 508 parsing
machinery renders `requirements.txt` entries identically, so switching between `pyproject.toml`
and a requirements file changes nothing about hover/diagnostic/completion behavior for an
otherwise-identical requirement string.

## Custom/Private Indexes

A PyPI/pip dependency whose applicable index is overridden via `requirements.txt`
`--index-url`/`--extra-index-url`, Poetry's `[[tool.poetry.source]]`, or uv's
`[tool.uv.index]`/`[tool.uv.sources]` gets the same hover/diagnostic/completion
value a plain `pypi.org` dependency gets — instead of showing no version data, or
(before this feature) silently checking the wrong (public) index.

**Resolution order — the security-relevant rule**: whether an explicit
`--index-url` (or Poetry `primary`/`default`-priority source, or a uv index with
`default = true`) is present in the file determines the order every plain
dependency is checked in:

- **An explicit primary is declared**: that index is checked first, then every
  `--extra-index-url`/supplemental source, in declaration order. No implicit
  `pypi.org` hop is appended — `--index-url` *replaces* the default index (matching
  pip's own semantics), so a file that wants `pypi.org` reachable alongside an
  explicit primary must list it as an extra itself.
- **No explicit primary, but extras exist**: declared extras are checked *before*
  the implicit `pypi.org` fallback, which is always checked last. This is
  deliberately the reverse of what might seem intuitive, and is the whole point of
  this feature's design: it stops a private-only package's name from ever being
  sent to `pypi.org` before the user's own declared index has had a chance, and
  stops a same-named public package from silently shadowing a private one the user
  explicitly configured (the "dependency confusion" attack shape). This diverges
  from pip's own resolver, which pip's docs describe as having no defined
  precedence between `--index-url` and `--extra-index-url` and explicitly warn is
  unsafe for private packages for exactly this reason.

uv's `default = true` index follows this same "no explicit primary" shape: it is
uv's own lowest-priority, last-resort index — checked *after* every other declared
uv index, replacing the implicit `pypi.org` slot, never checked first the way an
explicit `--index-url` primary is.

**Poetry named sources**: a dependency declaring `source = "<name>"` (Poetry) or a
`[tool.uv.sources] <dep> = { index = "<name>" }` binding (uv) resolves directly
against that one named source, with no fallback to any other index — a deliberate,
single-hop route. A Poetry source with no `priority` key is treated as `primary`
(matching current Poetry documentation); `explicit`-priority Poetry sources and
`explicit = true` uv indexes are reachable only by name, never auto-included in the
extras chain.

**Authentication**: phase 1 carries **no** authentication at all — the same
Cargo/npm precedent. Any index URL with embedded userinfo (`https://user:pass@…`)
is rejected outright rather than stripped-and-used; `keyring`/`.netrc` are not
detected or acknowledged. This means an auth-gated private feed (e.g. Azure
Artifacts) is not reachable end-to-end until a follow-up auth spec ships — the
routing/fallback mechanism itself still works correctly for any unauthenticated
private index (an internal mirror behind network-level access control, or a devpi
instance with anonymous read).

**Fail-closed on misconfiguration**: an explicit `--index-url`, Poetry
primary/named source, or uv `default`/named index that fails validation (not
`https`, malformed, or blocked by the reachability policy below) shows no version
data for every affected dependency — never a silent fallback to `pypi.org`. An
invalid `--extra-index-url`/supplemental/non-default entry, by contrast, is simply
dropped from the fallback chain (with a logged warning) rather than failing the
whole dependency closed, since an extra is additive/optional by definition — the
remaining valid hops (including the implicit `pypi.org` fallback, if applicable)
still serve the dependency.

**Availability trade-off of the security fix above**: a genuine transport error
(timeout, 5xx, connection refused) on any hop — including a declared extra that
happens to be hop 0 in the no-explicit-primary case — halts resolution for that
dependency rather than silently falling through to the next hop. Applied to a file
with only `--extra-index-url` entries, an unreachable extra (a developer off the
corporate VPN, say) means every dependency in that file loses its version data,
including ordinary public ones with no relation to the private index. This is
intentional, not a bug: falling through on a transport failure would send every
affected package's name to `pypi.org` precisely when the private index is merely
unreachable — the same disclosure the resolution-order rule above exists to
prevent. A distinguishable log message ("extra index unreachable — resolution
halted, not falling back to pypi.org") accompanies this case so it can be told
apart from a genuinely missing package.

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented in [Cargo](cargo.md#customprivate-registries) — the same
`"public_only"`/`"off"`/`"all"` values, the same shared process-wide `HttpCache`
policy. Only *explicitly-declared* indexes (a primary, every extra, every named
source) are gated; the implicit `pypi.org` fallback used by the no-explicit-primary
case is never itself subject to this setting, since it is the same public-tier
client every plain dependency already uses. What this means in practice depends on
whether the file declares an explicit `--index-url` primary:

- **No explicit primary, extras only**: `workspace_registries = "off"` blocks
  every declared extra, and — since there is no implicit-fallback slot to lose —
  every plain dependency in the file degrades gracefully to resolving against
  `pypi.org` directly, exactly as if the file declared nothing at all.
- **An explicit `--index-url` primary**: an explicit primary *replaces* the
  default index rather than adding to it (FR-005(a)), so there is no implicit
  `pypi.org` hop to fall back to. If `off` blocks that primary, it fails closed
  (`CustomRegistry`, FR-006) and **every** dependency in the file loses version
  data — `off` does not silently degrade to public resolution here, unlike the
  extras-only case above.

**Known limitations**:
- Editing a file's index declarations does not take effect until it is next
  reparsed (edited, or the document reopened) — there is no dedicated file watcher
  for it yet.
- `pip.conf`/`pip.ini` and `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL` environment
  variables are not read at all — a project relying solely on those (rather than
  in-file `--index-url` flags) sees no improvement from this feature.
- `-r`/`-c` include propagation is not implemented: a file included via `-r
  base.txt` does not inherit the includer's index declarations, and vice versa.
- A `[tool.uv.sources]` binding is only recognized for the `index = "<name>"`
  shape — `git =`, `path =`, and `workspace = true` bindings are a distinct
  concept (dependency provenance, not registry routing) and are not read.
- **Cosmetic limitation**: a plain dependency in an extras-only file is classified
  as resolved via the alternate-index chain at parse time, before the winning hop
  is actually known — if it ends up resolving via the implicit `pypi.org`
  fallback, its hover heading still omits the `pypi.org` project link (the same
  suppression a genuinely private dependency gets). No data-correctness impact.

## Environment Markers (PEP 508)

When a Python dependency is gated by an environment marker (e.g., `numpy>=1.24; python_version>='3.9'`), the hover popup displays:
```
Active when: python_version >= '3.9'
```
This helps you understand when conditional dependencies apply. Markers are shown for dependencies in `pyproject.toml` (PEP 621), Poetry `[tool.poetry.dependencies]` tables, and both PEP 621 requirement strings and Poetry string-form suffixes.

## `requirements.txt` / `constraints.txt`

Files matching `requirements*.txt`, `*-requirements.txt`, `*.requirements.txt`, or `constraints*.txt` — or any `.txt` file directly inside a directory literally named `requirements/` (e.g. `requirements/base.txt`, `requirements/dev.txt`) — are routed to the PyPI ecosystem and parsed line-by-line (pip's requirements file format), reusing the same PEP 508 machinery as `pyproject.toml` — hover, diagnostics, markers and extras render identically across both. Comments, blank lines, `\`-continuations, per-requirement options (`--hash=...`), and recognized pip options (`-r`, `-c`, `-e`, `--index-url`, `--pre`, etc.) are handled; a `-r`/`-c`/`--requirement`/`--constraint` target is surfaced as a clickable `documentLink` resolved relative to the containing file's directory (ctrl/cmd-click to open it — its own dependencies are still checked only once it's open, not transitively from the referencing file). A pinned dependency (`django==5.0.1`) keeps its `==` pin on "update version" instead of widening to a range. Because neither the filename-pattern routing nor the `requirements/` directory convention is a fixed name, a non-manifest file that happens to match (e.g. a `product-requirements.txt` prose document, or a requirements-engineering docs file under an unrelated `requirements/` folder) is detected via a content heuristic and produces no hover/diagnostics/network requests — a file matched only via the `requirements/` directory convention requires a stronger signal (a recognized pip option, or a dependency with a version/URL) than a basename match does, since directory-name routing alone is weaker evidence that the file is really a Python manifest.

## Package-Name Completion

Package-name completion (issue #419) serves unranked, alphabetically-sorted prefix
matches from an in-memory index of PyPI's full Simple API project list (~882k names,
no popularity ranking) — the same approach PyCharm's PyPI completion uses, since PyPI
removed its XML-RPC search API and offers no first-party ranked search. The index is
built lazily (on the first completion request in a Python manifest) and once per
process, not refreshed on a timer.

Two behaviors worth knowing:
- **Completions insert the PEP 503 normalized spelling**, not the project's display
  spelling — `Django` is offered (and inserted) as `django`, `Zope.Interface` as
  `zope-interface`. This matches what `pip install` and both `poetry.lock`/`uv.lock`
  already normalize to.
- **Matching is prefix-only against the package name**, not a project's import name
  or description — typing `yaml` will not surface `pyyaml`, `sklearn` will not
  surface `scikit-learn`, and `bs4` will not surface `beautifulsoup4`. This is a
  known, common PyPI-specific expectation gap; a substring/import-name-aware search
  is tracked as a possible follow-up, not implemented here.

Because the index is capped and alphabetically sorted rather than ranked, the LSP
response for a package-name completion request sets `isIncomplete: true` so editors
re-query as the user keeps typing (`resolves #427`). This is scoped to the
package-name search itself — other completions in a Python manifest (versions,
comments, `[build-system]` positions) report `isIncomplete: false` like every other
ecosystem, since their result sets are already exhaustive.

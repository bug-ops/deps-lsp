# Go

## GOPROXY/GOPRIVATE Support

A Go module dependency whose applicable proxy is overridden via a `$GOENV`
`GOPROXY=` entry, or whose module path matches a `$GOENV` `GOPRIVATE=` glob
pattern, gets the same hover/diagnostic/completion value a
`proxy.golang.org`-resolved dependency gets — instead of showing no version
data, or (before this feature) silently checking the wrong (public) proxy.

**Resolution**: `$GOENV` is read once per process — the `GOENV` environment
variable if set and non-empty, else the platform default
`os.UserConfigDir()/go/env` (`~/.config/go/env` on Linux/macOS,
`%AppData%\go\env` on Windows), matching `go env -w`'s own file. `GOPROXY` is
parsed as a comma-or-pipe-separated ordered chain of hops (`go help goproxy`
semantics), recognizing the `direct` and `off` sentinels; when absent, the
existing hardcoded `https://proxy.golang.org` default applies unchanged.
`GOPRIVATE` is a comma-separated list of `path.Match`-style glob patterns
(`go help goprivate`) matched against a module's full path — a matching
module bypasses the entire `GOPROXY` chain and routes straight to the
`direct` terminal hop, regardless of what `GOPROXY` is configured to.

**`direct`/`off` show no data (phase 1 limitation)**: `deps-go` has no
direct-VCS resolution mechanism (no `go-import` meta-tag discovery, no
arbitrary-VCS client), so both the `direct` sentinel and `off` are
implemented as fail-closed terminal hops — the chain-fallback mechanics are
correct (a proxy hop's explicit not-found response falls through to the
next hop, including `direct`/`off`), but neither sentinel itself produces
version data. This preserves `GOPRIVATE`'s confidentiality guarantee (a
private module path is never sent to any proxy hop) even though no
replacement data is shown yet.

**Authentication**: phase 1 carries **no** authentication at all — the same
Cargo/npm/PyPI precedent. A `GOPROXY` hop URL with embedded userinfo
(`https://user:pass@…`) is rejected outright rather than stripped-and-used;
`.netrc` and a bare local-filesystem-path hop are not detected or
acknowledged.

**Fail-closed on misconfiguration**: a `GOPROXY` hop that fails validation
(not `https`, malformed, or blocked by the reachability policy below) is
dropped from the chain (with a logged warning) when other valid hops
remain; if every hop turns out invalid, the whole chain fails closed
(no version data for any affected dependency) — never a silent fallback to
`proxy.golang.org`. A transport failure (timeout, 5xx, connection refused)
on any hop halts resolution for that dependency rather than silently
falling through to the next hop, mirroring [PyPI](pypi.md#customprivate-indexes)'s
identical trade-off for the same reason: falling through would risk resolving a
private module through a fallback the reachability state does not actually
support.

**`,` vs `|` separator semantics**: the two `GOPROXY` separators are not
interchangeable — each governs a different fallback trigger for the hop
transition it precedes, matching `go help goproxy`/`modfetch/proxy.go`:
- `,` falls through to the next hop **only on an explicit not-found
  response** (`404`/`410`) — a transport failure (timeout, 5xx, connection
  refused) on that hop halts resolution for the dependency instead (see
  above).
- `|` falls through to the next hop on **any** error from that hop,
  including a transport failure.

A single `GOPROXY` value may mix both (e.g.
`GOPROXY=https://a.example|https://b.example,direct`); each transition
between two consecutive, *valid* hops keeps the separator that preceded
it, so a chain can combine "skip on any failure" and "skip only when
genuinely absent" hop-to-hop as needed.

When an invalid hop is dropped (per the fail-closed rule above) between
two surviving hops, the separators on either side of the dropped entry
are merged, with the more permissive one (`|`) winning: for example,
`GOPROXY=https://a.example|not-a-valid-url,https://c.example` records `|`
for the `a` -> `c` fallback, not the `,` that happened to follow the
dropped entry — a "skip on any failure" the user wrote is never silently
narrowed to "skip only when not found" just because the hop in between
turned out invalid.

**Reachability policy**: governed by the same `registries.workspace_registries`
setting documented in [Cargo](cargo.md#customprivate-registries). The default
public chain (`https://proxy.golang.org,direct`) used when `$GOENV` declares no
`GOPROXY` override is never subject to this gate — it is the same
ungated public-tier client `deps-go` already uses today. A hop blocked by the
policy surfaces the same informational diagnostic every other ecosystem's
blocked registry does (issue #958), naming the blocked host class independently
of any other invalid hop earlier in the chain — one diagnostic per document,
since `GOPROXY` is a single config-global declaration rather than a
per-dependency one.

**Known limitations**:
- Editing `$GOENV` does not take effect until the affected `go.mod` is next
  reparsed (edited, or the document reopened) — there is no dedicated file
  watcher for it yet.
- Live `GOPROXY`/`GOPRIVATE`/`GONOSUMCHECK`/`GOFLAGS` process environment
  variables (as opposed to the `$GOENV` file) are not read.
- `GOSUMDB`/`GONOSUMCHECK` checksum-database verification is out of scope
  entirely — no ecosystem crate in this project performs integrity
  verification today.
- Package-*name* completion is unconditionally a no-op for a dependency
  resolved to a non-default `GOPROXY` chain or a `GOPRIVATE`-routed
  module — Go has no package-name search endpoint in its module-proxy
  protocol at all.

# Go

`deps-go` provides LSP support for Go modules.

## Basics

| | |
|---|---|
| Manifest file | `go.mod` |
| Lock file (in-use version) | `go.sum` (module content-checksum lines, skipping the `/go.mod`-suffixed checksum-only lines) |
| Registry | Go module proxy — `proxy.golang.org` by default (`/{module}/@v/list`, `/{module}/@v/{version}.info`, `/{module}/@latest`) |
| Version syntax | Go's own module versioning (semver-based, including pseudo-versions like `v0.0.0-20230101000000-abcdef123456`) |

```go
require (
    github.com/gin-gonic/gin v1.9.1
)
```

Hovering a `require` line's version shows the latest module version from the proxy and a link
to its pkg.go.dev page; an outdated requirement gets an inlay hint and a diagnostic with an
"Update to latest version" code action. `require`/`replace`/`exclude` directives, both the
single-line and grouped `(...)` block forms, are all parsed with position tracking.

## `replace` Directives to a Filesystem Path

A module `replace`d to a local filesystem path (`replace acme.com/mod => ./local/mod`) is
classified as a non-registry dependency rather than defaulting to `proxy.golang.org` — the
classification applies to the module's `require` entry too, not only the `replace` line
itself, so the same module is not fetched under its original `require`d version while its
replacement is correctly skipped. A dependency resolved this way is never sent to the
proxy, drops its pkg.go.dev hover link, and is excluded from OSV vulnerability scanning
against the public module path (resolves #1202). A `replace` to a remote module at a
pinned version (not a filesystem path) is unaffected and remains registry-resolvable.

**Known limitation**: two `replace` directives for the same module path (a malformed or
mid-edit `go.mod`) collapse to whichever is parsed last, with no diagnostic.

## GOPROXY/GOPRIVATE Support

A Go module dependency whose applicable proxy is overridden via `GOPROXY`, or
whose module path matches a `GOPRIVATE` or `GONOPROXY` glob pattern, set in the
process environment or in `$GOENV`, gets the same hover/diagnostic/completion value a
`proxy.golang.org`-resolved dependency gets — instead of showing no version
data, or (before this feature) silently checking the wrong (public) proxy.

**Precedence**: each setting (`GOPROXY`, `GOPRIVATE`, `GONOPROXY`, `GOSUMDB`,
`GONOSUMDB`) is taken from the process environment when that variable is set and
non-empty, otherwise from `$GOENV`, as `go env` does. An empty variable falls through to
the file; a whitespace-only `GOPROXY` is not empty and fails closed. `GOENV=off` disables
the file only, process variables still apply. The process environment is read once at
startup, so a variable exported later needs a restart of the server. `GONOPROXY` defaults to
`GOPRIVATE` (the first non-empty of env `GONOPROXY`, file `GONOPROXY`, env `GOPRIVATE`,
file `GOPRIVATE`), so a `GONOPROXY` in the file beats a `GOPRIVATE` in the environment.

**Resolution**: `$GOENV` is read once per process — the `GOENV` environment
variable if it is an absolute path, else the platform default
`os.UserConfigDir()/go/env` (`~/.config/go/env` on Linux/macOS,
`%AppData%\go\env` on Windows), matching `go env -w`'s own file. `GOENV=off` disables the
file, as it does for `go` itself, and an empty `GOENV` is unset (the default file is read), while a relative `GOENV` is ignored without
falling back to the default (a relative path would resolve against a directory a repository can
influence). `GOPROXY` is
parsed as a comma-or-pipe-separated ordered chain of hops (`go help goproxy`
semantics), recognizing the `direct` and `off` sentinels; when absent, the
existing hardcoded `https://proxy.golang.org` default applies unchanged.
`GOPRIVATE` and `GONOPROXY` are comma-separated lists of `path.Match`-style glob
patterns (`go help goprivate`) matched against a module's full path — a module matching
the effective `GONOPROXY` bypasses the entire `GOPROXY` chain and routes straight to the
`direct` terminal hop, regardless of what `GOPROXY` is configured to.

A module that matches `GOPRIVATE` or `GONOSUMDB` while `GOPROXY` is unset is bypassed as
well, even when `GONOPROXY=none` excludes it: Go would ask `proxy.golang.org` for it, this
server deliberately does not, so a private path is never sent to a public service. With
`GOPROXY` set explicitly (even to `https://proxy.golang.org,direct`) and `GONOPROXY=none`,
the module is fetched through that chain, which counts as operator consent.

**Bypassed modules**: a module that is bypassed (matched by `GOPRIVATE`, `GONOPROXY` or
`GONOSUMDB`) or that has no proxy to ask (`GOPROXY=direct` or `GOPROXY=off`) is never looked
up. The server logs `fetch skipped: not looked up` at debug level instead of a Go-proxy 404
warning, and shows no "Unknown package" diagnostic for it.

**Vulnerability and supply-chain signals**: modules fetched through a `GOPROXY` chain keep
OSV and deps.dev coverage when their content is verified by the public checksum
database: `GOSUMDB` unset or `sum.golang.org`/`sum.golang.google.cn` (with an optional
`+key` and sumdb-proxy URL), and the module matches neither `GONOSUMDB` nor `GOPRIVATE`.
`GOSUMDB=off` or a custom checksum database, combined with a `GOPROXY`, turns these
signals off for the chain's modules, because a private checksum database proves nothing
about public content. A chain made only of `off`/`direct` is treated the same way: the go
command still verifies origin fetches against the checksum database, so those modules are
scanned unless `GOSUMDB=off`, `GONOSUMDB` or `GOPRIVATE` excludes them. A module matching
only `GONOSUMDB`, while every `GOPROXY` hop was rejected, is treated as an unverified mirror:
nothing is scanned and the CLI counts it as not checked (hover shows no footer, because the
module has no resolvable registry).

**Disclosure**: with `GOPROXY` set to a chain with a URL, `direct` or `off` hop (from the process
environment or from `go env -w`), the names of modules not matched by `GOPRIVATE` or
`GONOSUMDB` are sent to OSV.dev (on by default) and, on hover, to deps.dev, exactly as for a
user without `GOPROXY`. With `GOPROXY=off`, a private module not listed in `GOPRIVATE` or
`GONOSUMDB` goes to OSV.dev as well, the same as with no `GOPROXY`. Set `GOPRIVATE` or `GONOSUMDB`
for private module paths, or turn the OSV and `supply_chain` features off. Users who only had `go env -w GOPROXY=...` and no
`GOPRIVATE` previously sent nothing for such modules; that changed with process-environment
support, intentionally, for parity with users without `GOPROXY`.

**Empty and whitespace values**: as in Go, a whitespace-only list variable (for example
`GOPRIVATE=" "`) is set, matches nothing, and shadows the `$GOENV` list. With `GOPROXY`
unset, private modules are then treated as public. An explicit
`GOPROXY=https://proxy.golang.org,direct` plus a `GONOSUMDB`-only module sends that module
to `proxy.golang.org`, while an unset `GOPROXY` bypasses it.

**Version lists**: each proxy hop is asked for `/@v/list`, as the go command does, so older pins,
"Newer version available" and the recent-versions list work as they do without a `GOPROXY`. A hop that
answers `404`/`410` (or an empty list) for `/@v/list` falls back to `/@latest`; that one-entry list is
too incomplete to call a pin unsatisfiable, so no `unsatisfiable-requirement` warning is raised for it.

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

**Proxies.** The `GOPROXY` chain comes from your `$GOENV` or process environment, which you own, so it is an
[operator-owned registry](../configuration.md#operator-owned-registries): it follows your system
proxy like the public registries. Workspace-guarded traffic stays direct by default (see
[Proxies and guarded registry traffic](../configuration.md#proxies-and-guarded-registry-traffic)).

**Reachability policy**: every `GOPROXY` hop comes from your `$GOENV` or process environment, so it is trusted and
**ignores `registries.workspace_registries`, including `"off"`**, and may resolve to a private
address under `"public_only"` (see [Operator-owned registries](../configuration.md#operator-owned-registries)).
A hop whose host is never a registry (loopback, link-local, cloud-metadata, unspecified,
reserved) is still refused under every setting, by the shared
[connect-time message](cargo.md#customprivate-registries). A hop blocked this way halts a `,`
chain with that message; in a `|` chain a later not-found or error does not hide it. The default
public chain (`https://proxy.golang.org,direct`) used when neither declares a
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
- `GOFLAGS` and `$GOROOT/go.env` defaults (Go 1.21+) are not read.
- A `GOPROXY` with embedded userinfo fails closed for every module, whether it comes from
  the process environment or from `$GOENV`.
- Checksum-database verification itself is out of scope — no ecosystem crate in this
  project performs integrity verification; `GOSUMDB`/`GONOSUMDB` only decide whether a
  proxied module counts as public content for OSV and deps.dev.
- Package-*name* completion is unconditionally a no-op for a dependency
  resolved to a non-default `GOPROXY` chain or a `GOPRIVATE`-routed
  module — Go has no package-name search endpoint in its module-proxy
  protocol at all.

# Key API Contracts

## No `async_trait`

All trait methods use `BoxFuture` instead of `#[async_trait]`:

```rust
// Correct
fn parse_manifest<'a>(
    &'a self,
    content: &'a str,
    uri: &'a url::Url,
) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResult>>> {
    Box::pin(async move { ... })
}

// Wrong — do not use
#[async_trait]
async fn parse_manifest(&self, content: &str, uri: &url::Url) -> Result<Box<dyn ParseResult>> { ... }
```

> **Note:** manifest/lock-file URIs are plain [`url::Url`](https://docs.rs/url), not
> `tower_lsp_server::ls_types::Uri` — `deps-lsp` converts an LSP `Uri` to a `url::Url` once at
> the document boundary, so every `Ecosystem`/`ParseResult`/`LockFileProvider` method below
> works with `url::Url` throughout.

## Position Tracking

Use `deps_core::lsp_helpers::LineOffsetTable` for byte offset to LSP position conversion:

```rust
use deps_core::lsp_helpers::LineOffsetTable;

let table = LineOffsetTable::new(content);
let position = table.byte_offset_to_position(content, byte_offset);
```

## `LockFileProvider` Signatures

```rust
impl LockFileProvider for MyLockParser {
    fn locate_lockfile(&self, manifest_uri: &url::Url) -> Option<PathBuf> { ... }
    fn parse_lockfile<'a>(&'a self, lockfile_path: &'a Path)
        -> Pin<Box<dyn Future<Output = Result<ResolvedPackages>> + Send + 'a>> { ... }
}
```

## Registry Client Method Naming (issue #834)

A registry crate's own struct (`{Ecosystem}Registry`) exposes concrete, non-boxed **inherent**
methods alongside its `deps_core::Registry` trait impl — the trait's own method of the same
name should delegate to the inherent one (see [Step 5: Implement the Registry
Client](step-5-registry.md)). A new ecosystem crate must use this exact vocabulary for a new
operation; a different name for one of these same operations is the #760/#834 bug class:

| Operation | Canonical name |
| --- | --- |
| Fetch all versions | `get_versions` |
| Fetch all versions plus extra data (e.g. publish dates) | `get_versions_with` |
| Fetch the version matching a requirement | `get_latest_matching` |
| Search by query | `search` |
| Register an alternate/private registry source | `register_alternate` |
| Build the registry's web-display URL for a package | `package_url` (re-export from `lib.rs`) |
| Construct a client pointed at a non-default base URL | `with_base` |
| Pure in-memory getter (no I/O) | no `get_` prefix (Rust API Guidelines C-GETTER) |

**Sanctioned, named exceptions** (a deliberate #834 scope decision, not drift to fix):
- `gem_url` (`deps-bundler`), `crate_url` (`deps-cargo`), `jsr_package_url` (`deps-deno`) —
  ecosystem-specific display-URL builder names are fine to keep; only the *re-export*
  consistency (every `package_url`-named builder living in `lib.rs`) was in scope.
- The metadata-fetch **return type** stays per-ecosystem (`GemInfo`/`PackageInfo`/
  `ArtifactInfo`/`CrateInfo`/`DenoMetadata`/`GoMetadata`, ...) — only the *method* name
  converges on `get_package_metadata`; the six type names are unrelated data shapes with no
  shared field set, and unifying them is a separate, much larger design exercise this issue
  did not take on.

See `deps_core::Registry`'s own "Registry client API contract" doc section for the full
rationale, and `deps_core::registry_conformance!`'s `ty:` form to add a compile-time check
that your crate's registry struct exposes the first four names as true inherent methods
(not merely reachable through a trait — see `deps_core::conformance::NotInherent`'s doc).
Wired into 9 of the 14 ecosystem crates directly (`deps-maven`'s check transitively covers
`deps-gradle`, which reuses `deps-maven`'s `MavenCentralRegistry` unchanged); `deps-go`/
`deps-github-actions` (no search endpoint to call at all — an inherent `search` would be a
fabricated stub existing only to pass this check) and `deps-deno`/`deps-gitlab-ci` (no
single struct the check's assumptions fit) are exempt, with the exact reasoning in
`deps_core::Registry`'s own doc.

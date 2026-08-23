# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- Removed unused `async-trait` workspace dependency from root `Cargo.toml` and 10 crate manifests (never invoked via `#[async_trait]`; native async traits used throughout) (#159)

## [0.10.1] - 2026-08-20

### Removed
- **Breaking (pre-1.0, internal API)**: deleted dead ecosystem-specific error variants, constructor helpers, and `DepsError`⇄ecosystem `From` conversions across all 11 registry-integrated crates. Evidence: none of these types were referenced by any consumer outside their own crate's `error.rs` (verified via workspace-wide `rg`), and registry code across the crates already returned `deps_core::DepsError` in 8 of 11 cases — the deleted variants existed only to be immediately round-tripped back into a `DepsError` with a lossier message, or were never constructed at all. Per-crate:
  - **deps-cargo**: `CargoError::{InvalidVersionSpecifier, PackageNotFound, RegistryError, ApiResponseError, InvalidStructure, MissingField, WorkspaceError, CacheError, Other}` and their constructor helpers; `impl From<DepsError> for CargoError`. Kept: `TomlParseError`, `InvalidUri`.
  - **deps-npm**: `NpmError::{InvalidVersionSpecifier, PackageNotFound, RegistryError, ApiResponseError, InvalidStructure, MissingField, CacheError, Other}` and their constructor helpers; `impl From<DepsError> for NpmError`. Kept: `JsonParseError`.
  - **deps-pypi**: `PypiError::{InvalidVersionSpecifier, PackageNotFound, RegistryError, ApiResponseError, MissingField, CacheError, Other}` and their constructor helpers; `impl From<DepsError> for PypiError`. Kept: `TomlParseError`, `InvalidDependencySpec`, `UnsupportedFormat`.
  - **deps-go**: `GoError::{ParseError, ModuleNotFound, RegistryError, CacheError, InvalidPseudoVersion, ApiResponseError, Io, Other}` and their constructor helpers; `impl From<DepsError> for GoError`. Kept: `InvalidModulePath`, `InvalidVersionSpecifier`.
  - **deps-swift**: the entire `SwiftError` type and its `Result` alias (`src/error.rs` deleted) — `ParseError`, `InvalidVersionSpecifier`, `RegistryError`, `GitHubApiError`, `Io`, all constructor helpers, and both `DepsError` conversions. `crate::registry`/`crate::parser` now use `deps_core::Result` directly; nothing in the crate constructed these variants in production.
  - **deps-dart**: `DartError::{InvalidVersionConstraint, PackageNotFound, RegistryError, ApiResponseError, InvalidStructure, InvalidUri, CacheError, Other}`; `impl From<DepsError> for DartError`. Kept: `ParseError`.
  - **deps-maven**: `MavenError::{InvalidVersion, PackageNotFound, RegistryError, ApiResponseError, InvalidCoordinates, CacheError, Io, Other}`; `impl From<DepsError> for MavenError`. Kept: `ParseError`.
  - **deps-nuget**: `NuGetError::{InvalidVersion, PackageNotFound, RegistryError, ServiceIndexError, ApiResponseError, CacheError, Io, Other}`; `impl From<DepsError> for NuGetError`. Kept: `ParseError`.
  - **deps-composer**: `ComposerError::{PackageNotFound, RegistryError}`. Kept: `JsonParseError`, `Io`.
  - **deps-bundler**: the entire `BundlerError` type and its `Result` alias (`src/error.rs` deleted, 100% dead — no variant was ever constructed outside its own tests). `crate::parser::parse_gemfile` now returns `deps_core::Result` directly.
  - **deps-gradle**: unchanged (`ParseError`, `InvalidDependency`, `Maven`, `Io` were all already live or structurally required by the `deps-maven` cross-crate `From` chain).

### Added
- **deps-core**: `DepsError::PackageNotFound { package, registry }`, `DepsError::HttpStatus { url, status }`, and `DepsError::ApiResponse { package, registry, source }` — structured replacements for the string-stuffed `CacheError`/`ParseError` wrapping the deleted ecosystem variants used to produce. `HttpStatus` reconstructs the HTTP reason phrase (e.g. "Not Found") in its `Display` from the stored `u16` via `reqwest::StatusCode::canonical_reason`, so the status code is now structurally matchable via `matches!(err, DepsError::HttpStatus { status: 404, .. })`. Message text is not byte-identical to the `CacheError` it replaces: the `"cache error: "` prefix is dropped (see the `HttpCache` bullet below), and a non-canonical status code (e.g. Cloudflare 520-530) no longer carries the `<unknown status code>` suffix `reqwest::StatusCode`'s own `Display` used to append — a 520 response now reads `HTTP 520 for {url}` instead of `HTTP 520 <unknown status code> for {url}`.
- **deps-cargo, deps-npm, deps-pypi, deps-go, deps-bundler, deps-dart, deps-maven, deps-nuget, deps-composer, deps-swift**: `pub const REGISTRY: &str` naming the backing registry for `DepsError::PackageNotFound`/`ApiResponse` construction (`"crates.io"`, `"npm"`, `"PyPI"`, `"Go proxy"`, `"RubyGems"`, `"pub.dev"`, `"Maven Central"`, `"NuGet"`, `"Packagist"`, `"GitHub"` respectively). **deps-gradle** re-exports `deps_maven::registry::REGISTRY` rather than defining its own, since it resolves through `MavenCentralRegistry`.

### Changed
- **deps-core**: `HttpCache`'s two non-2xx response paths (`conditional_request_with_headers`, `fetch_and_store_with_headers`) now return `DepsError::HttpStatus` instead of `DepsError::CacheError(format!("HTTP {status} for {url}"))`. The status code is now matchable via `matches!(err, DepsError::HttpStatus { status: 404, .. })` instead of substring-matching the formatted message, but the message text itself changes: `CacheError`'s `Display` prepended `"cache error: "` to every non-2xx message across all 11 ecosystems, which `HttpStatus` drops (e.g. `"cache error: HTTP 404 Not Found for {url}"` -> `"HTTP 404 Not Found for {url}"`); both changes are intentional cleanup, not an oversight.
- **deps-pypi**: fixed a latent bug (`registry.rs` `get_versions`/`get_package_metadata`) where not-found detection matched the literal substring `"404"` in the formatted error message — a non-404 failure whose message happened to embed "404" (e.g. via the request URL, or a package name like `pytest-404`) was misclassified as not-found. Replaced with a structural match on `DepsError::HttpStatus { status: 404, .. }`. Not-found message wording also changed from `Package '{name}' not found on PyPI` to `{name} not found on PyPI` (dropped the `Package '...'` quoting, now shared with every other ecosystem's not-found message via `DepsError::PackageNotFound`).
- **deps-go**: fixed the 404 path, which previously did not work at all — `GoError::ModuleNotFound` existed but was never constructed, so a 404 module lookup surfaced as `deps-lsp: failed to parse registry for {module}: cache error: HTTP 404 Not Found for <url>` (a parse-error wrapper around a cache error, not a not-found error). It now surfaces as `deps-lsp: {module} not found on Go proxy` via `DepsError::PackageNotFound`, matching PyPI. Non-404 registry failures (network errors, 5xx, etc.) also lose the `"failed to parse registry for {module}: "` wrapper and now surface the underlying `DepsError` (e.g. an `HttpStatus` or `RegistryError` message) directly instead of being mislabeled as a parse failure.
- **deps-swift**: `SwiftRegistry::get_versions` previously detected a GitHub rate limit by substring-matching `"HTTP 403"` in the formatted error text — the same anti-pattern as the PyPI bug, fixed while this code path was already being migrated off `SwiftError`. Now matches structurally on `DepsError::HttpStatus { status: 403, .. }`. A GitHub 404 (repo not found) now also maps to `DepsError::PackageNotFound` instead of surfacing as a raw `HttpStatus`, matching every other ecosystem. This migration also changed several message strings, previously untracked here:
  - `validate_owner_repo`'s malformed-input error moved from `SwiftError::RegistryError` (wrapped into `DepsError::ParseError{file_type: "GitHub API for {name}"}`, rendering `"failed to parse GitHub API for {name}: invalid owner/repo format: '{name}'"`) to `DepsError::InvalidUri` (`"invalid URI: invalid owner/repo format: '{name}'"`) — `CacheError` was used transiently and has been corrected to `InvalidUri`, since this is input validation, not a cache or registry failure.
  - The 403 rate-limit message drops the `"GitHub API 403:"` marker its `CacheError`-wrapped predecessor had (message content is otherwise unchanged, still describes the rate limit and how to set `GITHUB_TOKEN`).
  - The GitHub error-body passthrough (`parse_tags_response`) changes `"GitHub API 0: {msg}"` to `"GitHub API error: {msg}"` — an improvement, since the old text embedded a bogus status `0` that was never a real HTTP status.
- **deps-npm**: `NpmRegistry::get_versions` now requests the abbreviated packument (`Accept: application/vnd.npm.install-v1+json`) instead of the full packument, cutting response size by roughly 60% (verified live against `express`: 804,975 bytes full vs 339,376 bytes abbreviated) with no change to the parsed `NpmVersion` data (the abbreviated format still carries per-version `deprecated`). Also wires up 404 detection, previously missing for npm: a nonexistent package now surfaces as `DepsError::PackageNotFound` instead of a raw `HttpStatus` (resolves #162)
- **deps-pypi**: `PypiRegistry::get_versions` now uses the PEP 691 Simple API (`https://pypi.org/simple/{package}/`, `Accept: application/vnd.pypi.simple.v1+json`) instead of the full JSON API, cutting response size by roughly a third (verified live against `django`: 619,755 bytes full vs 411,376 bytes Simple API). The Simple API's top-level `versions` array supplies the version list directly; per-version yanked status is derived from each `files[].filename` since the Simple API carries `yanked` per-file rather than per-version — a version counts as yanked if any of its files are. `PypiRegistry::get_package_metadata` (hover: summary, project URLs) is unchanged, still backed by the full JSON API (resolves #162)
- **deps-pypi**: `build_yanked_map`'s per-file version matching was O(files × versions) — measured live against `boto3` (2,098 versions / 4,196 files): 140.7ms of blocking CPU per call on every hover/diagnostics/completion request touching the package, with no `spawn_blocking` around it. Replaced the whole-filename substring scan with `parse_version_from_filename`, which derives a file's version directly from PyPI's `{name}-{version}[-...].{ext}` filename structure in O(filename length), cutting the measured cost to ~1.8ms for the same `boto3` response (verified against a saved live response). The old scan is kept only as a last-resort fallback for filenames that don't parse this way. This also fixes two live correctness bugs the old scan had: it could misattribute a file to an unrelated numeric-looking tag elsewhere in the filename (e.g. `pyobjc_core-2.2-py2.6-macosx-10.3-fat.egg` resolving to version `"10.3"` instead of `"2.2"`, since `"10.3"` is longer and the scan tried longest-first over the whole string), and it missed files whose filename spells a version differently than its PEP 440 canonical form (e.g. `protobuf-4.21.0_rc_1-...whl` for canonical `4.21.0rc1`) since it only ever did exact/substring string comparison — the new path adds a PEP 440-normalized comparison tier for exactly this case.
- **deps-pypi, deps-npm**: package names were interpolated into registry request URLs (`get_versions`'s Simple API/JSON API/registry URLs) without percent-encoding, inconsistent with `package_url()` in the same crates, which already encodes. `normalize_package_name` (PyPI) collapses `-`/`_`/`.` but leaves `/`, `?`, `#` untouched, and npm's `get_versions` used the raw, unnormalized name outright. Added `simple_api_url`/`metadata_url` (deps-pypi) and `versions_url` (deps-npm), mirroring `package_url`'s encoding — including npm's per-segment `@scope/name` handling for scoped packages — so a crafted package name can no longer redirect the request to a different path/query on the same trusted host or cause cache-key collisions.

### Fixed
- **deps-nuget**: the `✅`/`❌ {latest}` inlay hint (and the matching diagnostic) never flagged `.csproj` `PackageReference` or `Directory.Packages.props` `PackageVersion` entries as outdated, even a full major behind the latest release — only `packages.config` detected outdated versions correctly. Root cause: `EcosystemFormatter::version_satisfies_requirement`, reused as the "is this dependency up to date" check when no lock-file-resolved version is present, treats a bare NuGet `Version="X.Y.Z"` (and its explicit open-ended-minimum spellings `[X.Y.Z,)`/`(X.Y.Z,)`/`[X.Y.Z,]`) as a minimum floor (per NuGet semantics), so it returns `true` for any published version `>= X.Y.Z` and can never signal "there's a newer version" for floor-pinned entries. Added `EcosystemFormatter::is_requirement_up_to_date`, a new defaulted trait method (default: unchanged `version_satisfies_requirement(latest, requirement)` behavior, zero change for every other ecosystem) that separates "does the requirement accept this version" from "is the pin itself behind latest"; `NuGetFormatter` overrides it to classify on the *parsed range shape* (any minimum-only range, bracketed or bare) rather than the requirement string's leading character, and reports outdated only when `latest` is strictly newer than the floor — a floor already ahead of `latest` (a preview/prerelease pin, or a registry regression) is left alone rather than rendered as a downgrade suggestion. Exact pins (`[1.0.0]`), bounded ranges (`[1.0,2.0)`), and floating patterns (`1.1.*`) keep the existing satisfies-based check. This also changes the outdated-detection behavior of the public `deps_core::lsp_generate_diagnostics` API, which now delegates to `is_requirement_up_to_date` instead of comparing the registry's latest-matching version against the latest stable version (resolves #163)
- **deps-core, deps-cargo, deps-npm, deps-pypi, deps-bundler, deps-go, deps-composer, deps-dart, deps-nuget, deps-maven, deps-swift**: `generate_hover` interpolated manifest-controlled and registry/lockfile-controlled text (dependency name, version requirement, marker expression, current/latest/recent version strings) directly into Markdown link and code-span syntax with no escaping, letting a crafted manifest entry (e.g. a package name containing `](https://evil.example)[`, a bare `<https://evil.example>` autolink, or an embedded newline that terminates the hover's heading line early) render a live attacker-controlled link in the editor's hover popup — a phishing/typosquat vector. Added `deps_core::lsp_helpers::escape_markdown` (backslash-escapes every ASCII punctuation character — not just brackets/parens — and replaces control characters, including newlines, with a space so the text cannot terminate the single-line heading it's embedded in), applied to the hover link label. Backslash-escaping does not work inside inline code spans (CommonMark §6.1), so added a separate `deps_core::lsp_helpers::markdown_code_span` helper (dynamically widens the backtick fence past the longest run in the content instead) for the `**Current**`, `**Requirement**`, `**Active when**`, `**Latest**`, and recent-versions-list fields. Every `EcosystemFormatter::package_url`/registry `package_url` implementation now percent-encodes the package name before embedding it in the link target (preserving legitimate structural separators — npm's `@scope/name`, Composer's `vendor/package`, Maven/Gradle's `group:artifact`, Go's `module/path` — while escaping everything else, including `%` itself), and `deps-swift`'s `Registry::package_url` now validates against the same `owner/repo` pattern its formatter already used, closing the same injection vector on the URL side (resolves #160)
- **deps-core**: `build_package_completion` (completion-item documentation, shown while typing a package name — no malicious manifest required, only registry search results) interpolated `Metadata::name`/`latest_version`/`description`/`repository`/`documentation` directly into Markdown with no escaping, the same injection class as #160's hover fix. Reused the existing `deps_core::lsp_helpers::escape_markdown` helper on all five fields, so a crafted registry name, version, description, or link URL can no longer break out of the bold header or the `[Repository](...)`/`[Documentation](...)` link syntax to splice in a live attacker-controlled link or raw HTML. `description`'s 200-char truncation (`floor_char_boundary`) is applied before escaping, not after, so truncation cannot land mid-escape-sequence (resolves #167)
- **deps-dart**: `yaml_rust2::YamlLoader::load_from_str` (crate `yaml-rust2` 0.12) has no recursion/depth limit and no public API to configure one for its block-style (indentation-driven) sequence/mapping parser — it overflows the native thread stack (SIGABRT, killing the whole `deps-lsp` process) on a deeply nested `pubspec.yaml`/`pubspec.lock`, before any Dart-specific parsing runs. Bisected against the real `yaml-rust2` recursion on a 2 MiB debug stack: compact block-sequence chaining (`- - - - 1`, the cheapest attack at 2 bytes/level) aborts at depth 4536; growing-indent block mappings (`k:\n k:\n  k:\n...`), the tightest case, abort at depth 1994. Added `deps_core::check_yaml_nesting_depth`, a single-pass, non-recursive structural scan (bounds flow-style `[`/`{` bracket depth and block-style indentation/compact-dash nesting into one shared depth budget, skipping quoted-string and comment content) that rejects input nested past `deps_core::MAX_YAML_NESTING_DEPTH` (64, matching `MAX_TOML_NESTING_DEPTH` — a >30x margin under the tightest observed crash, still far deeper than any real `pubspec.yaml`/`pubspec.lock` needs) before it reaches `YamlLoader::load_from_str`. Wired into both `deps-dart` YAML parse sites: `parse_pubspec_yaml` and `parse_pubspec_lock` (resolves #173)
- **deps-dart**: independent of nesting depth, `yaml_rust2::YamlLoader::on_event_impl` (crate `yaml-rust2` 0.12) deep-clones the whole anchored subtree once per `Event::Alias` reference, and again into its internal `anchor_map` for every anchored node — a shallow (constant-depth) YAML document with a chain of anchors, each aliasing the previous anchor twice, expands exponentially in the memory actually allocated (classic "billion laughs"), OOM-killing the whole `deps-lsp` process on a payload only a few hundred bytes long; `check_yaml_nesting_depth` (#173) cannot catch this since nesting depth stays constant throughout. `YamlLoader` exposes no allocation budget. Added `deps_core::check_yaml_expansion`, a pre-pass driven by the same `yaml-rust2` `Parser`/event stream `YamlLoader::load_from_str` itself uses (so anchor ids and event order match exactly), tallying the total bytes the real load would allocate — including the anchor-clone and alias-clone duplication — and rejecting once the tally exceeds `deps_core::MAX_YAML_EXPANDED_BYTES` (32 MiB). This must be a byte budget, not a node-count budget (the first version of this fix used node count and was caught in review): a single large scalar anchor aliased many times allocates megabytes per alias while costing only one node each, so a node-count budget let a ~1 MB payload exhaust hundreds of gigabytes. A raw-text `&anchor`/`*alias` scan was also tried first and rejected: it false-positived on ordinary prose such as `description: A widget *multiplier* helper`. Wired into both `deps-dart` YAML parse sites (`parse_pubspec_yaml`, `parse_pubspec_lock`), after the existing depth guard and before `YamlLoader::load_from_str` (resolves #175)

## [0.10.0] - 2026-08-20

### Added
- **deps-pypi**: hover for a dependency gated by a PEP 508 environment marker (e.g. `numpy>=1.24; python_version>='3.9'`) now shows an "Active when: `<marker>`" line. `PypiDependency.markers_range` is now populated with the marker expression's source span (PEP 621 requirement strings, Poetry table-form `markers = "..."`, and Poetry string-form `; <marker>` suffixes), derived from the TOML value's own span for UTF-16-correct, escape- and formatting-agnostic positions — following the same pattern as `version_range`/`extras_range` (resolves #134)
- **New ecosystem: NuGet (.NET)** — `deps-nuget` adds support for `.csproj`/`.fsproj`/`.vbproj` (`PackageReference`, both attribute and child-element form, with central package management entries degrading to no version requirement), `Directory.Packages.props` (`PackageVersion`), `packages.config` (normalized to an exact-pin range at parse time), and `packages.lock.json` lock files. Backed by the NuGet V3 registry API (service index resolution, flat-container version enumeration, `SearchQueryService` search). Version comparison is hand-rolled (4-component `Major.Minor.Patch.Revision`, SemVer2 prerelease precedence with case-insensitive labels, interval and floating-version syntax) since no maintained crate supports NuGet's scheme
- `deps_core::Ecosystem` gained `manifest_extensions()`, a defaulted trait method (empty by default, zero behavior change for existing ecosystems) letting an ecosystem route by file extension when the manifest basename is unbounded (e.g. `*.csproj`). `EcosystemRegistry::get_for_filename` now falls back to a case-insensitive extension lookup after an exact filename match misses

### Changed
- **deps-core, deps-cargo, deps-npm, deps-go, deps-pypi, deps-bundler, deps-dart, deps-swift, deps-nuget, deps-composer**: deduplicated the `tokio::fs::read_to_string` + `DepsError::ParseError` wrapping boilerplate repeated across all 9 lock file parsers into one shared `deps_core::lockfile::read_lockfile_content` helper. **Behavior delta**: `deps-composer`'s lock file read error previously reported bare `file_type: "composer.lock"` without the file path, unlike the other 8 parsers; it now includes ` at {path}` like every other ecosystem — no test asserted the old string (resolves #121)
- **deps-core, deps-lsp**: bundled the `cached_versions`/`resolved_versions` `&HashMap<String, String>` pair, passed together at every LSP response call site, into one `deps_core::VersionData<'a>` struct (`lsp_helpers::generate_inlay_hints`, `lsp_helpers::generate_hover`, `lsp_helpers::generate_diagnostics_from_cache`, and the corresponding `Ecosystem` trait default methods — `generate_inlay_hints`, `generate_hover`, `generate_diagnostics` — plus `deps-lsp` handlers. `lsp_helpers::generate_diagnostics`, the separate registry-fetching free function, is unaffected — it never took these two maps). Removes the risk of silently swapping the two same-typed arguments at a call site. Also dropped `Ecosystem::generate_code_actions`'s `_cached_versions` parameter, which was already unused (never forwarded to `lsp_helpers::generate_code_actions`) (resolves #119, partial — `PackageName`/`VersionReq` newtypes and the `Dependency`/`DependencyInfo` trait unification tracked in follow-up issues)
- Bump `yaml-rust2` 0.11 → 0.12 (routine dependency update, no functional changes) (resolves #115)
- Bump `h2` (transitive, via `reqwest`/`hyper`) 0.4.15 → 0.4.17, patching RUSTSEC-2026-0258 (unbounded empty DATA frames) (resolves #116)
- **Breaking (pre-1.0, internal API)**: removed dead `deps_lsp::document` types that never had a production call site — the duplicate 4-variant `Ecosystem` enum (`DocumentState.ecosystem` is now `deps_core::EcosystemId`, resolves #118), `UnifiedDependency` and `DocumentState`'s always-empty `dependencies` field, plus the now-unreferenced `deps_core::delegate_to_variants!` macro (resolves #144), and `UnifiedVersion` and `DocumentState`'s dead `versions` field, superseded by the existing `cached_versions`/`update_cached_versions` path (resolves #153). Each type only ever modeled 4 of the project's 11 ecosystems. Construct `DocumentState` via `new_from_parse_result`/`new_without_parse_result`, which now take `ecosystem: EcosystemId` directly instead of a stringly-typed `ecosystem_id: &'static str` (follow-up to #144). None of this is part of any wire format, so it only affects direct Rust callers of `deps-lsp` as a library

### Fixed
- **deps-lsp**: completion (both the primary parsed-manifest path and the raw-text fallback) is now bounded by a dedicated 2s timeout instead of sharing the generic 30s HTTP client timeout, so a slow registry no longer blocks `textDocument/completion` for up to 30s (resolves #147). Fallback prefix extraction also no longer leaks a literal `"` into the registry search query when the cursor sits inside or right after a quoted dependency key in `package.json`/`composer.json`, which previously suppressed exact-name matches (resolves #148)
- **deps-pypi**: the `MAX_MARKER_LEN` byte cap introduced for #133 bounded marker text length but not paren-nesting depth — a marker under the byte cap could still reach ~1000 levels of nesting, still handed to `pep508_rs`'s unbounded recursive-descent marker parser (uncatchable Rust stack overflow, aborts the whole process; shipped release builds already survived the maximum depth reachable under the byte cap with ~4x stack margin, but debug builds did not). Added a `MAX_MARKER_DEPTH = 32` guard (`marker_too_deep`) alongside the byte-length check, applied consistently to both marker call sites (PEP 621 requirement strings and Poetry `markers` tables/suffixes); over-deep markers now fall back to raw text like over-long ones already did. The depth scanner tracks quote state matching `pep508_rs`'s own tokenizer, so `(`/`)` characters inside a quoted marker value (e.g. `extra==')'`) are not miscounted as real nesting — closing a gap where the naive byte-count guard could be bypassed by an attacker-controlled quoted payload (resolves #146)
- **deps-core, deps-cargo, deps-pypi, deps-gradle**: `toml_span::parse` (crate `toml-span` 0.7.1) has no recursion/depth limit and no public API to configure one — its recursive-descent array/inline-table parser overflows the native thread stack (SIGABRT, killing the whole `deps-lsp` process) on a deeply nested TOML literal (e.g. `dependencies = ` followed by ~2000+ nested `[`), before any ecosystem-specific parsing runs. Added `deps_core::check_toml_nesting_depth`, a single-pass, non-recursive structural scan (skips bracket characters inside single- and multi-line string literals — including a `"""`/`'''` body that legally ends with 1-2 extra literal quote characters before its closing delimiter, per the TOML spec — and line comments) that rejects input nested past `deps_core::MAX_TOML_NESTING_DEPTH` before it reaches `toml_span::parse`. Wired into all 6 `toml_span::parse` call sites: `deps-cargo`'s `Cargo.toml`, `Cargo.lock`, and workspace-root-discovery ancestor-directory scan (the last skips an over-deep ancestor `Cargo.toml` rather than aborting the whole parse, preserving usability for the file the user actually opened), `deps-pypi`'s `pyproject.toml`/lock file parsers, and `deps-gradle`'s version catalog parser. `MAX_TOML_NESTING_DEPTH` is 64, not the originally-shipped 256: lock file parsing runs inside `tokio::spawn` on a 2 MiB `tokio` worker stack, not the 8 MiB main thread manifest parsing uses, and nested inline tables (`{a={a=...}}`) exhaust that smaller stack noticeably faster than nested arrays in a debug build — bisected against the real `toml_span` recursion, a debug build survives depth 220 for inline tables on a 2 MiB stack, so 256 was already past the unsafe threshold for that call site/shape/profile combination. 64 leaves a >3x margin under that figure while still being far deeper than any real manifest needs (the deepest nesting observed across 2716 real-world `.toml` files sampled from a local Cargo registry cache was 3). `check_toml_nesting_depth` also bounds dotted-key and dotted-table-header segment counts (`a.b.c = 1`, `[a.b.c]`), not just `[`/`{` bracket depth: each `.`-separated segment drives one level of `toml-span` table recursion with zero bracket characters, so a bracket-only scan scored a payload like `[package.a.a.a...]` (hundreds of segments) as depth 0 and let it straight through to `toml_span::parse`, which still stack-overflowed — this affected release builds too, not just debug, since a ~3.6 KB dotted-key/header lockfile aborted a release build on a 2 MiB worker stack. Dots are only counted in key position (line start, inside a header, or right after `{`/`,` while the innermost open bracket is `{`), never in value position, so `a = 3.14` and dotted version/date values are unaffected. `deps-lsp`'s `tokio` worker thread stack size is also now set to 8 MiB (matching the main thread) as defense-in-depth on top of the depth guard, removing the asymmetry where identical content was safe on the manifest-parsing main thread but fatal on the lock-file-parsing worker thread (resolves #150)
- **deps-core**: `HttpCache` response bodies are now read via a streaming `Response::chunk()` loop capped at 32 MiB (`DepsError::ResponseTooLarge`) instead of unbounded `Response::bytes()`, closing a memory-exhaustion vector (CWE-400) that a `Content-Length` pre-check couldn't have caught since reqwest's `gzip` feature strips that header after decompression (resolves #123). The near-duplicate `_with_headers`/non-`_with_headers` request paths were also collapsed into one implementation each; the surviving conditional-request path now rejects a non-2xx/non-304 refresh response (e.g. a `503`) instead of silently caching it over the existing good entry (stale-while-revalidate fallback still returns the untouched stale entry) (resolves #120)
- **deps-pypi**: PEP 508 environment markers are now normalized and surfaced consistently across all manifest syntaxes instead of being dropped or shown misleadingly. PEP 621 requirement-string markers, previously parsed and discarded, now serialize back onto `PypiDependency.markers` via `MarkerTree::try_to_string()` (resolves #122); Poetry table-form and string-form markers normalize through the same `MarkerTree` path, falling back to raw text on parse failure instead of being passed through unnormalized or silently dropped, and `version_range`/`markers_range` are derived from the TOML value's own span so they no longer overlap or land at the wrong offset for unusual formatting (quoted keys, escaped quotes, non-ASCII, missing space around `=`) (resolves #133). Marker expressions are also length-capped before reaching `pep508_rs`'s unbounded recursive-descent parser, since an oversized/deeply nested expression can overflow the stack or take multiple seconds to parse; oversized markers fall back to raw text
- **deps-maven, deps-gradle**: version comparison and sorting now matches Maven's actual precedence rules instead of falling back to raw ASCII/lexicographic comparison at several points. A purely numeric segment always outranks a non-numeric one (bare-qualifier legacy tags like Guava's `r03`..`r09` no longer outrank numeric releases, resolves #125); a version's own prerelease qualifier always sorts below its base release regardless of segment-count padding (resolves #127); qualifier words are ranked via Maven's `ComparableVersion.QUALIFIERS` table (`alpha < beta < milestone < rc/cr < snapshot < release < sp`, case-insensitive) instead of alphabetically, with a glued numeric suffix compared numerically (`M2` vs `M10`, `alpha9` vs `alpha15`) and `is_prerelease` derived from the same table (resolves #130, #131); and qualifiers are now tokenized on every alpha/digit boundary rather than only the trailing digit run, so embedded transitions (`rc1a`, `2beta` vs `beta2`) rank correctly (resolves #137)
- **deps-core, deps-lsp**: ecosystem identity was threaded through `deps-lsp` as a bare string in several places that did an incomplete match instead of an exhaustive one. `DocumentState::new_from_parse_result`/`new_without_parse_result` silently mistagged any of 7 ecosystems (bundler, dart, maven, composer, gradle, swift, nuget) as `Cargo` on an unmatched id; `completion::is_in_dependencies_section` silently disabled section-aware completion filtering (always `false`) for 8 ecosystems (the same 7, plus `go`, which its old match also missed); `completion::create_package_completion_item` silently inserted Cargo's `name = "version"` TOML syntax for the same 8 ecosystems regardless of their actual manifest format. Added `deps_core::EcosystemId`, an exhaustive enum covering all 11 registered ecosystems with `Display`/`FromStr` interop with `Ecosystem::id()`, and switched all three call sites (plus the legacy 4-variant `deps_lsp::document::Ecosystem`, now removed — see Changed) to match on it — a future ecosystem missing from any of these matches is now a compile error. `is_in_dependencies_section` also gained real raw-text section detection for composer, maven, go, and dart (previously only cargo/pypi/npm were handled); `create_package_completion_item` gained a correctly-formatted insert snippet for every ecosystem. bundler/swift/gradle/nuget still return `false` from `is_in_dependencies_section` (matching pre-fix behavior) since none of the four has a single unambiguous raw-text section marker to detect against — real detection for them is left as a follow-up (resolves #118)
- **CI**: the `test` job's matrix `include` entries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` matched the same base `(ubuntu-latest, stable)` combination, so the second silently overwrote the first — `x86_64-unknown-linux-musl` was never actually checked in CI. Cross-compile checks (both musl targets plus `aarch64-pc-windows-msvc`) now run in a dedicated `cross-check` job with no shared base matrix axis, so `include` entries can no longer collide (resolves #109)
- **tests**: native Windows test runs were never exercised in CI (the `windows-latest`/stable slot was always absorbed by the `aarch64-pc-windows-msvc` cross-compile job above), which hid that most test fixtures built `Uri`s from Unix-style absolute paths — not recognized as absolute on Windows, causing `Uri::from_file_path(...).unwrap()` to panic. Added `deps_core::test_util::test_uri`, a cross-platform test helper (feature-gated via `test-util`), and switched all executed test/doctest call sites to it

## [0.9.5] - 2026-08-12

### Changed
- **MSRV bumped to 1.91** — unlocks `str::floor_char_boundary`, used to simplify description truncation in `deps-core`

### Added
- **Release/CI**: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` release binaries, built via `cross`, covering musl-based Linux distributions (e.g. Alpine) alongside the existing glibc targets. CI gained matching build-only cross-compile checks for both musl targets

### Fixed
- **deps-npm**: version completion tests no longer assume `nonexistent-package`/`nonexistent-pkg` are unregistered on the live npm registry — npm now publishes a security-holding package under that exact name, which made `test_complete_versions_empty_prefix` flaky in CI. Tests use the same `this-package-does-not-exist-12345` placeholder already used elsewhere in the suite

### Security
- Upgrade `quick-xml` 0.39.4 → 0.41.0 to address RUSTSEC-2026-0195 (unbounded namespace-declaration allocation in `NsReader`)
- Upgrade `crossbeam-epoch` 0.9.18 → 0.9.20 to address RUSTSEC-2026-0204 (invalid pointer dereference in `fmt::Pointer` for `Atomic`/`Shared`)

## [0.9.4] - 2026-06-29

### Fixed
- **deps-maven, deps-gradle**: version completion now returns all available versions instead of only the current one — prefix extraction was slicing to value-end instead of cursor position (resolves #98)

### Security
- Upgrade `rustls-webpki` 0.103.11 → 0.103.12 to address RUSTSEC-2025-0174 and RUSTSEC-2025-0175
- Bump `rustls-webpki` 0.103.12 → 0.103.13
- Bump `rand` 0.9.2 → 0.9.4

## [0.9.3] - 2026-03-28

### Added
- **Cargo feature completion** — LSP now provides auto-completion for feature names inside `features = [...]` arrays in Cargo.toml dependency entries (resolves #82)

### Fixed
- **deps-cargo**: crate name completion now sorts search results by download count, so popular crates like `sqlx` and `thiserror` appear at the top instead of being buried or absent (resolves #95)
- Code action version update no longer produces doubled quotes in Cargo.toml (`""1.0.0""`) or doubled single quotes in Gemfile (`''1.0.0''`); `format_version_for_text_edit` now returns the bare version string since the TextEdit range already excludes delimiters
- **Cargo feature completion** — completion items no longer carry a `textEdit` with `range (0,0)-(0,0)`; the range was incorrect and caused strict LSP clients to insert text at the beginning of the file instead of at the cursor. `build_feature_completion` now accepts `Option<Range>` and omits `textEdit` when no range is provided, matching the behaviour of version completion (resolves #88)
- `deps-composer`: position tracking for packages out of alphabetical order — enable `serde_json`
  `preserve_order` feature so `composer.json` entries are iterated in file order rather than
  `BTreeMap` alphabetical order; previously, packages appearing earlier in the file but later
  alphabetically had `name_range`/`version_range` stuck at `(0,0)→(0,0)`, breaking hover,
  inlay hints, and diagnostics (#84)
- **deps-bundler**: `version_matches_requirement` now handles wildcard `"*"` requirement, fixing inlay hints always returning empty for Gemfile dependencies (resolves #89)
- **deps-maven**: packages with legacy non-semver versions (e.g. `guava` `r03`–`r09`) no longer report a wrong latest version; `<release>` from `maven-metadata.xml` is now used as the authoritative latest stable version, with sort-based fallback when the field is absent (resolves #91)

## [0.9.2] - 2026-03-21

### Fixed
- Add missing `offset_encoding` field to `InitializeResult` in LSP server

### Security
- Update `quinn-proto` 0.11.13 -> 0.11.14

## [0.9.1] - 2026-03-04

### Security
- Update `aws-lc-sys` 0.37.1 -> 0.38.0 (via `aws-lc-rs` 1.15.4 -> 1.16.1) to fix three high-severity vulnerabilities:
  - GHSA-hfpc-8r3f-gw53: PKCS7_verify Signature Validation Bypass
  - GHSA-65p9-r9h6-22vj: Timing Side-Channel in AES-CCM Tag Verification
  - GHSA-vw5v-4f2q-w9xf: PKCS7_verify Certificate Chain Validation Bypass

## [0.9.0] - 2026-02-23

### Added
- **PHP/Composer ecosystem support** — New `deps-composer` crate with full composer.json and composer.lock support
  - JSON parser for `require` and `require-dev` sections with position tracking
  - Platform package filtering (`php`, `ext-*`, `lib-*` excluded from registry lookups)
  - Packagist v2 API with metadata de-minification (field inheritance algorithm)
  - Packagist search API for package name autocomplete
  - Composer-specific version constraint matching: tilde (`~1.2` = `>=1.2.0 <2.0.0`), caret, wildcard (`1.0.*`), OR (`||`), ranges
  - Case-insensitive package name normalization (`vendor/package`)
  - composer.lock parser for `packages` and `packages-dev` sections
  - URL-safe registry queries with proper encoding per path segment
  - Feature-gated registration in deps-lsp (`composer`)
- **Swift/SPM ecosystem support** — New `deps-swift` crate with full Package.swift and Package.resolved support
  - Regex-based Package.swift parser covering all 9 `.package()` call signatures (from, upToNextMajor, upToNextMinor, exact, half-open range, closed range, branch, revision, path)
  - Comment stripping with byte-offset preservation for accurate LSP positions
  - Multiline `.package()` call support
  - GitHub API registry — version resolution via repository tags, package search via GitHub Search API
  - Package identity as `owner/repo` extracted from Git URLs
  - Version requirements normalized to semver ranges at parse time
  - Package.resolved lockfile support for all 3 schema versions (v1, v2, v3)
  - Owner/repo validation to prevent URL injection in GitHub API calls
  - Feature-gated registration in deps-lsp (`swift`)

## [0.8.0] - 2026-02-23

### Added
- **Gradle ecosystem support** — New `deps-gradle` crate with support for three manifest formats
  - Version Catalog parser (`gradle/libs.versions.toml`) via toml-span with reliable span tracking
  - Kotlin DSL parser (`build.gradle.kts`) via regex
  - Groovy DSL parser (`build.gradle`) via regex
  - Reuses `MavenCentralRegistry` from deps-maven (no registry duplication)
  - Parses `[versions]`, `[libraries]` sections with `version.ref` resolution
  - Recognizes all Gradle configurations: implementation, api, compileOnly, runtimeOnly, testImplementation, etc.
  - Feature-gated registration in deps-lsp (`gradle`)
- **Gradle variable resolution** — `$var` and `${var}` in `build.gradle`/`build.gradle.kts` resolved from `gradle.properties` (walks parent directories)
- **settings.gradle parsing** — Extract plugin dependencies from `pluginManagement { plugins { } }` blocks (Groovy and Kotlin DSL)
- **Google Maven repository support** — Android packages (`androidx.*`, `com.google.firebase.*`, `com.google.android.*`, `com.android.*`) now resolve from Google Maven instead of Maven Central
- **Gradle Plugin Portal fallback** — Packages not found on Maven Central are now retried on `plugins.gradle.org/m2`, resolving 404 errors for Gradle-exclusive plugins

### Changed
- **Migrate deps-cargo and deps-pypi from toml_edit to toml-span** — Reliable span tracking for all values including inline tables; eliminates text-search fallbacks for position tracking
- Remove `toml_edit` from workspace dependencies (all TOML parsers now use `toml-span`)
- Extract `LineOffsetTable` and `position_in_range` to deps-core for reuse across ecosystems
- Extract `complete_package_names_generic` to deps-core completion module
- **Architectural refactoring** — Remove legacy trait system and eliminate code duplication across 8 ecosystem crates (closes #68):
  - Delete `handler.rs` and legacy `PackageRegistry`, `VersionInfo`, `PackageMetadata` traits from deps-core
  - Add `fn formatter(&self)` required method to `Ecosystem` trait; default LSP handler implementations for `generate_inlay_hints`, `generate_hover`, `generate_code_actions`, `generate_diagnostics` — eliminating ~400 duplicate lines across ecosystems
  - Replace `#[async_trait]` with `BoxFuture` pattern in `Ecosystem`, `Registry`, and `LockFileProvider` traits (dyn-safe, no async_trait allocations)
  - Centralize `MockDep`/`MockParseResult` test helpers in `deps-core::lsp_helpers` tests (was duplicated 11 times)
  - Remove conflicting duplicate `Version`/`Metadata` impls from `deps-dart` and `deps-bundler` types modules

## [0.7.1] - 2026-02-22

### Added
- **Maven ecosystem support** — New `deps-maven` crate with pom.xml parsing and Maven Central integration
  - SAX parser via quick-xml with byte-accurate position tracking
  - Parses `<dependencies>`, `<dependencyManagement>`, and `<build><plugins>` sections
  - Maven property resolution from `<properties>` section including built-in `project.version`, `project.groupId`, `project.artifactId`
  - maven-metadata.xml CDN fetch for version lookup (50-150ms vs 300-800ms Solr)
  - Maven Solr search API for package search (full-text)
  - Maven version comparison with prerelease qualifier detection (alpha, beta, RC, SNAPSHOT)
  - `groupId:artifactId` as canonical package identifier
  - Feature-gated registration in deps-lsp (`maven`)

### Fixed
- **DashMap deadlock in HttpCache** — Release shard read lock before awaiting conditional requests to prevent deadlock under concurrent fetches
- **LSP progress backpressure** — Channel-based progress architecture with `try_send` prevents registry fetches from stalling on LSP transport
- **False "Unknown package" during loading** — Skip diagnostics while versions are still being fetched
- **Pre-release-only packages** — Fall back to latest pre-release when no stable version exists

### Changed
- Default `max_concurrent_fetches` increased from 5 to 20
- Default `fetch_timeout_secs` reduced from 10 to 5

## [0.7.0] - 2026-02-16

### Added
- **Dart/Pub ecosystem support** — New `deps-dart` crate with full pubspec.yaml and pubspec.lock support
  - YAML parser with position tracking via yaml-rust2
  - pub.dev API client for package info and search
  - pubspec.lock parser for installed version resolution
  - Dart version constraint matching (caret, range, any, exact) with correct 0.x semantics
  - Hosted, git, path, and SDK dependency sources

### Changed
- **Workspace dependencies updated** — reqwest 0.12 -> 0.13, tokio 1 -> 1.49, toml_edit 0.22 -> 0.25, yaml-rust2 0.10 -> 0.11

### Fixed
- **Cargo parser panic on multi-byte UTF-8** — Adjust search_start to char boundary when slicing content for dependency name lookup
- **Dart wildcard version matching** — Treat `"*"` as wildcard alias for `"any"` in version constraint matching

## [0.6.1] - 2026-02-16

### Added
- **deps-bundler benchmarks** — Criterion benchmarks for Gemfile/Gemfile.lock parsing with various file sizes (5-100 deps)

### Changed
- **CI migrated to moonrepo/setup-rust** — Replaced dtolnay/rust-toolchain and Swatinem/rust-cache with unified moonrepo action
- **Simplified codecov upload** — Single upload with path-based flags (8 actions → 1)
- **Removed sccache from CI** — moonrepo handles caching natively

### Fixed
- **deps-bundler test coverage increased to 90%+** — Added comprehensive tests for error handling, parser edge cases, registry response parsing
- **Lock file duplicate versions** — ResolvedPackages now stores all versions per package name and returns the highest semver version, fixing incorrect outdated status when both direct and transitive dependency versions coexist

## [0.6.0] - 2026-02-03

### Added
- **Ruby/Bundler ecosystem support** — New `deps-bundler` crate with full Gemfile and Gemfile.lock support
  - Gemfile DSL parser with regex-based extraction
  - Gemfile.lock parser with state machine for GEM, GIT, PATH sections
  - rubygems.org API client with HTTP caching
  - Version comparison with pessimistic operator (`~>`)
  - Support for git, path, github dependency sources
  - Group handling (development, test, production)
  - Implements Ecosystem, Dependency, Version, Metadata traits from deps-core

### Fixed
- **"Unknown package" false positives** — Packages present in lock file no longer show "Unknown" diagnostic when registry fetch fails
- **Platform-specific gems** — Gemfile.lock DEPENDENCIES section is now parsed to recognize platform-specific gems (e.g., `tzinfo-data` on Windows/JRuby)

### Changed
- Zed extension now supports Ruby language for Gemfile files
- Updated deps-bundler README with usage examples

## [0.5.5] - 2026-01-27

### Fixed
- **Inlay hints now correctly handle cached versions** — Fixed bug where inlay hints showed all green checkmarks after cargo update or code actions
  - Removed incorrect overwriting of cached_versions with resolved_versions in handle_lockfile_change (server.rs)
  - Removed incorrect merging of resolved_versions into cached_versions in handle_document_change (lifecycle.rs)
  - cached_versions now correctly preserve latest registry versions while resolved_versions track lock file versions
- **Inlay hints for dependencies not in lock file** — Dependencies missing from Cargo.lock now show correct status based on version requirement satisfaction
  - Two-tier check: lock file versions compared directly, missing dependencies checked against version requirements
  - Fixes incorrect red cross display for dev-dependencies in workspace members

### Changed
- Updated dependencies (aws-lc-rs, aws-lc-sys, cc, colored, and others)

## [0.5.4] - 2026-01-15

### Fixed
- **Inlay hints now based on lock file version** — Shows ✅ only when lock file has the latest version, ❌ otherwise (regardless of manifest requirement)

## [0.5.3] - 2026-01-15

### Changed
- **Improved inlay hints logic** — Shows ❌ only when code action is needed (requirement doesn't allow latest), ✅ when requirement allows latest (just need lockfile update)
- **Enhanced version_satisfies_requirement** — Proper handling of caret (^) and tilde (~) semantics
  - `^X.Y.Z` where X > 0: allows any `X.*.*`
  - `^0.Y.Z`: allows only `0.Y.*`
  - `^0.0.Z`: allows only `0.0.Z` exactly
  - `~X.Y.Z`: allows only patch-level changes
- **NPM formatter simplified** — Now uses default trait implementation for version matching
- **Diagnostics use cached versions** — Eliminates redundant network calls during diagnostic generation

### Fixed
- PyPI `"*"` specifier handling — PEP 440 requires empty string for "any version"
- Go.sum parser now uses "last occurrence wins" semantics (matches Go toolchain behavior)
- Caret version matching for `^0.x.y` edge cases

### Added
- Unit tests for `generate_diagnostics_from_cache` function
- Unit tests for caret version edge cases (`^0.2`, `^0.0.3`)
- Test for PyPI `"*"` specifier normalization
- OpenSSL license added to deny.toml (required by aws-lc-sys via reqwest 0.13)

## [0.5.2] - 2025-12-27

### Changed
- **Unified version completion display** — Completion and code actions now share formatting
  - `VersionDisplayItem` struct for consistent version display metadata
  - `prepare_version_display_items()` for shared filtering logic (yanked, limit 5)
  - First version marked as "(latest)" with preselect in both features
- **Semantic version ordering** — Versions sorted by index, not lexicographically
  - Fixes "0.8.0" appearing after "0.14.0" in completion lists
- **Code deduplication** — Extracted `complete_versions_generic()` to deps-core
  - Consolidated ~220 lines of duplicated code across 4 ecosystem crates
  - Each ecosystem now specifies only operator characters

### Fixed
- Version completion for empty strings (`pkg = ""`) no longer deletes preceding text
  - Changed to insert mode when no text_edit range available

## [0.5.1] - 2025-12-26

### Changed
- **Ecosystem registration centralized** — All registration now uses macros in `lib.rs`
  - `ecosystem!()` macro for feature-gated re-exports
  - `register!()` macro for feature-gated runtime registration
  - Adding new ecosystem requires only 2 lines in lib.rs
- Updated ECOSYSTEM_GUIDE.md with new macro-based registration
- Updated deps-zed README with Go support

## [0.5.0] - 2025-12-26

### Added
- **Go modules support** — Full ecosystem support for Go packages (`deps-go` crate)
  - go.mod parser with position tracking for all directives
  - go.sum lock file parser for resolved versions
  - Support for `require`, `replace`, `exclude` directives
  - Indirect dependency detection (`// indirect` comments)
  - Pseudo-version parsing and display
  - proxy.golang.org registry client with HTTP caching
  - Module path escaping for uppercase characters
  - Inlay hints, hover, code actions, diagnostics
- Lockfile template added to ecosystem templates
- Formatter template added to ecosystem templates

### Changed
- **Feature flags for ecosystems** — Each ecosystem can now be enabled/disabled independently
  - `cargo` — Cargo.toml support (default: enabled)
  - `npm` — package.json support (default: enabled)
  - `pypi` — pyproject.toml support (default: enabled)
  - `go` — go.mod support (default: enabled)
- Updated ECOSYSTEM_GUIDE.md with Go examples and lockfile/formatter requirements
- Templates now include lockfile.rs.template and formatter.rs.template

## [0.4.1] - 2025-12-26

### Added
- Cold start support: LSP features now work when IDE restores files without sending didOpen
- Rate limiting for cold start requests (10 req/sec per URI, configurable)
- Background cleanup task for rate limiter (60s interval)
- ColdStartConfig for configuration (enabled, rate_limit_ms)
- 7 new integration tests for cold start scenarios
- LspClient test utility extracted to tests/common/mod.rs

### Changed
- Reduced MAX_FILE_SIZE from 50MB to 10MB for security
- Added LARGE_FILE_THRESHOLD (1MB) with warning logs
- Enhanced permission error logging

### Fixed
- LSP features not working when IDE opens with manifest files already open

## [0.4.0] - 2025-12-25

### Changed
- **BREAKING**: Migrated from `tower-lsp` to `tower-lsp-server` v0.23 (community fork)
  - Fixes server panics on cancelled LSP requests ([tower-lsp#417](https://github.com/ebkalderon/tower-lsp/issues/417))
  - `Url` type renamed to `Uri` throughout the codebase
  - Native async trait support (removed `#[async_trait]` attribute)
- Completion requests are now ~50ms faster (removed debounce workaround)
- Updated documentation and templates for new dependency

### Added
- Fallback completion for incomplete TOML/JSON when parsing fails
- Support for `[workspace.dependencies]` section in Cargo.toml
- MIT-0 license added to allowed licenses for new dependencies

### Fixed
- Server no longer crashes on rapid typing or cancelled requests
- Documents are now stored even when initial parsing fails
- Doctests updated for Uri type migration

## [0.3.1] - 2025-12-25

### Fixed
- Inlay hints now compare against absolute latest stable version, not just matching major.minor
- Pre-release versions filtered from "newer version available" diagnostics
- Background tasks no longer exit early due to `parse_result` being lost on clone

### Changed
- Extracted `find_latest_stable()` utility for consistent version comparison across features

## [0.3.0] - 2025-12-24

### Added
- **Trait-based ecosystem architecture** — Unified handling for all package ecosystems
  - `Ecosystem` trait with parser, registry, and formatter
  - `EcosystemRegistry` for dynamic ecosystem lookup by URI
  - `LockfileProvider` trait for lock file parsing
  - Simplified document lifecycle with generic handlers

### Changed
- **Performance optimizations** — Significant latency improvements
  - Parallel registry fetching with `futures::join_all` (97% faster document open)
  - O(N log K) cache eviction algorithm with min-heap (90% faster eviction)
  - Parse-once pattern for version sorting (50% faster parsing)
  - String formatting optimization with `write!()` macro
  - Early lock release pattern with `get_document_clone()`

### Fixed
- npm: Remove extra quotes in code action version replacements (#29)

## [0.2.3] - 2025-12-23

### Changed
- CI: Use `katyo/publish-crates` for automatic workspace publishing with dependency ordering

### Fixed
- CI: Add missing `deps-pypi` to crates.io publish workflow

## [0.2.2] - 2025-12-23

### Added
- **Lock file support** — Resolved versions from lock files
  - Cargo.lock parsing with version extraction
  - package-lock.json v2/v3 parsing for npm
  - poetry.lock and uv.lock parsing for PyPI
  - Hover shows resolved version from lock file
  - Inlay hints compare resolved version vs latest
- **PyPI/pyproject.toml support** — Full ecosystem support for Python packages
  - PEP 621 format (`[project.dependencies]`)
  - PEP 735 dependency groups (`[dependency-groups]`)
  - Poetry format (`[tool.poetry.dependencies]`)
  - Package name autocomplete from PyPI registry
  - Version hints and diagnostics

### Fixed
- PyPI parser: Correct version range position for normalized specifiers (pep508 adds spaces)

## [0.2.1] - 2025-12-22

### Fixed
- CI: Skip strip for cross-compiled binaries (aarch64-linux-gnu)

### Changed
- CI: Use trusted publishing for crates.io releases (OIDC)
- Use workspace dependency for deps-core in deps-cargo and deps-npm

## [0.2.0] - 2025-12-22

### Added
- **npm/package.json support** — Full ecosystem support for npm packages
  - Package name autocomplete from npm registry
  - Version hints and diagnostics
  - Hover information with version list
- **Multi-crate architecture** — Extracted shared code into reusable crates
  - `deps-core`: Shared types, HTTP cache, error handling, traits
  - `deps-cargo`: Cargo.toml parser and crates.io registry client
  - `deps-npm`: package.json parser and npm registry client
- **UX improvements**
  - Emoji indicators for version status (✅ up-to-date, ❌ outdated)
  - Version list in hover popup with docs.rs links
  - Multiple version options in code actions (up to 5)
  - Clickable links to crates.io/npmjs.com in inlay hints
- **Performance improvements**
  - Version caching in document state
  - FULL document sync for immediate file change detection
  - Parallel version fetching

### Fixed
- npm parser: Correct position finding for dependencies sharing version string (e.g., vitest)

### Changed
- MSRV bumped to 1.89 for let-chains support
- Refactored handlers to use let-chains for cleaner code
- Extracted deps-zed to [separate repository](https://github.com/bug-ops/deps-zed) as git submodule

## [0.1.0] - 2024-12-22

### Added
- **Cargo.toml support** — Full LSP features for Rust dependencies
  - Package name autocomplete from crates.io sparse index
  - Version autocomplete with semver filtering
  - Feature flag autocomplete
  - Inlay hints showing latest available versions
  - Diagnostics for unknown, yanked, and outdated packages
  - Hover information with package metadata
  - Code actions to update dependency versions
  - Support for `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
  - Support for `[workspace.dependencies]` section
- **LSP server infrastructure**
  - tower-lsp based implementation
  - HTTP cache with ETag/Last-Modified validation
  - Document state management with DashMap
  - Configuration system with serde deserialization
  - Error types with thiserror
- **Zed extension** (deps-zed)
  - WASM-based extension for Zed editor
  - Auto-download of pre-built binaries
- **Development infrastructure**
  - Test suite with cargo-nextest
  - Code coverage with cargo-llvm-cov
  - Security scanning with cargo-deny
  - CI/CD pipeline with GitHub Actions
  - Cross-platform builds (Linux, macOS, Windows)

### Security
- Zero unsafe code blocks
- TLS enforced via rustls
- cargo-deny configured for vulnerability scanning

[Unreleased]: https://github.com/bug-ops/deps-lsp/compare/v0.10.1...HEAD
[0.10.1]: https://github.com/bug-ops/deps-lsp/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/bug-ops/deps-lsp/compare/v0.9.5...v0.10.0
[0.9.5]: https://github.com/bug-ops/deps-lsp/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/bug-ops/deps-lsp/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/bug-ops/deps-lsp/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/bug-ops/deps-lsp/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/bug-ops/deps-lsp/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/bug-ops/deps-lsp/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/bug-ops/deps-lsp/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/bug-ops/deps-lsp/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/bug-ops/deps-lsp/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/bug-ops/deps-lsp/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/bug-ops/deps-lsp/compare/v0.5.5...v0.6.0
[0.5.5]: https://github.com/bug-ops/deps-lsp/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/bug-ops/deps-lsp/compare/v0.5.3...v0.5.3
[0.5.3]: https://github.com/bug-ops/deps-lsp/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/bug-ops/deps-lsp/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/bug-ops/deps-lsp/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/bug-ops/deps-lsp/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/bug-ops/deps-lsp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/bug-ops/deps-lsp/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/bug-ops/deps-lsp/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/bug-ops/deps-lsp/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/bug-ops/deps-lsp/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/bug-ops/deps-lsp/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bug-ops/deps-lsp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bug-ops/deps-lsp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bug-ops/deps-lsp/releases/tag/v0.1.0

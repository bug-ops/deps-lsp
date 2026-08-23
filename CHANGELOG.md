# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **deps-lsp**: new `textDocument/codeLens` support — a document-scoped "Update N outdated dependencies" lens on every open manifest with at least one safely-editable outdated dependency, bound to a new `deps-lsp.updateAllOutdated` command that applies a single batch `WorkspaceEdit`, version-guarded where the client capability allows it (resolves #170). Key pieces:
  - **deps-core**: `lsp_helpers::collect_update_all_edits` (re-exported as `deps_core::collect_update_all_edits`) is the single routine computing both the lens count and the edits the command applies, shared across all 11 ecosystems with zero ecosystem-crate changes. It reuses the same "outdated" predicate as `generate_diagnostics_from_cache` (a requirement already satisfied by `latest` is not rewritten — that lag is the lockfile's, not the manifest's) and adds a **literal-span safety guard**: before emitting an edit, the dependency's `version_range` is sliced from the manifest source and compared (mod whitespace, and NuGet's `[v]` bracket wrap) against the declared requirement text. Several ecosystems point `version_range` at something that is not the version literal itself — a Maven `${property}` reference, a Gradle DSL variable or `libs.versions.toml` catalog alias, or (for every Swift dependency form) the lower-bound literal of a synthesized comparator range — and the guard skips those dependencies entirely rather than corrupting the manifest. Accepted edits are sorted and asserted non-overlapping (a later edit overlapping an earlier one is dropped with a `tracing::warn!`). `lsp_helpers::generate_code_lenses` (re-exported as `lsp_generate_code_lenses`) wraps the edit count into zero or one `CodeLens`, and a new defaulted `Ecosystem::generate_code_lenses` method delegates to it via `self.formatter()`.
  - **deps-lsp**: new `handlers::code_lens` handler (mirrors `handlers::code_actions`); `DocumentState` gained a `version: Option<i32>` field populated from `didOpen`/`didChange` (`None` for documents loaded from disk during cold start); `code_lens_refresh()` notifications sent alongside every existing `inlay_hint_refresh()` call site; new `CodeLensConfig { enabled: bool }` (default `true`) under `DepsConfig.code_lens`.
  - `execute_command` refuses to act on `deps-lsp.updateAllOutdated` (no-op + a `window/showMessage` warning) unless the target document is loaded, not currently `Loading`, and has a known LSP version — the last condition specifically excludes documents populated from disk after a missed `didOpen` (server restart/crash), where the client's buffer may hold unsaved edits the disk copy does not reflect. The applied edit is emitted as versioned `WorkspaceEdit.document_changes` when the client advertises `workspace.workspaceEdit.documentChanges`, falling back to the untyped `changes` map otherwise.
  - Known trade-off, documented in `ECOSYSTEM_GUIDE.md`: `Package.swift`, and `pom.xml`/Gradle builds that version dependencies exclusively through properties, variables, or a version catalog, will show no lens even when genuinely outdated — the literal-span guard declines to edit a span it cannot prove is the version literal. Lifting this restriction requires moving the guard into the affected parsers (tracked as a follow-up), which is out of scope for this PR.
- **deps-core**: vulnerability-aware diagnostics via the OSV.dev batch API (`crates/deps-core/src/osv/`). `OsvClient` batches concrete dependency versions against `POST /v1/querybatch`, resolves matching advisories via `GET /v1/vulns/{id}`, and caches both query results (6h TTL) and advisory records (`modified`-timestamp invalidated) independently of `HttpCache`'s entry map, since OSV sends no `ETag`/`Last-Modified` validators. `EcosystemId::osv_ecosystem()` maps all 11 supported ecosystems to their OSV `package.ecosystem` string; `EcosystemFormatter::osv_package_name()` provides the (possibly ecosystem-specific) canonical package name sent on the wire, with overrides in `deps-composer` (lowercase) and `deps-swift` (`github.com/{owner}/{repo}`, gated on the dependency's source actually being a GitHub URL). Version selection is deliberately conservative: only `DependencySource::Registry` dependencies are queried, preferring the lock-file-resolved version and falling back to an already-concrete declared requirement, to avoid flagging a patched git/path fork or a version-range requirement with an invalid CVE. Diagnostics render one entry per advisory (capped at 5 + a "+N more" summary), severity capped at `WARNING` (never `ERROR`, since a vulnerable-but-valid manifest is not a parse error); hover adds a "Security advisories" section. Both surfaces are strict about the difference between "not scanned" (git/path dependency, unmappable name, network failure) and "scanned and clean" — an unscanned dependency never renders an affirmative "no known vulnerabilities" claim. The scan runs as a `tokio::spawn`ed background task alongside the existing registry version fetch in `deps-lsp`'s document lifecycle, so it never delays the inlay-hint refresh; a dependency flagged as vulnerable triggers a follow-up check of the latest registry version so hover can warn if updating would not actually resolve the advisory. Gated by the new `diagnostics.vulnerabilities_enabled` config option (default `true`).
- **deps-core, deps-lsp**: release-freshness signal (issue #145, PR1 of 2) — hover's "Recent versions" list appends a greyed-out relative age (e.g. `"2 hours ago"`) to each version whose registry supplies a publish timestamp, and version completion items carry the same age as `label_details`, gated end-to-end by `freshness.enabled`. New `deps-core` `freshness` module: `PublishTime` (a `Copy` newtype over Unix epoch seconds backed by the `time` crate, confined to `deps-core`), `DEFAULT_COOLDOWN_SECS` (3 days, mirroring GitHub Dependabot's default package cooldown), `is_within_cooldown` (`age < cooldown`, exclusive boundary), `format_relative_age`, and `FreshnessSettings` (a `Copy` DTO threaded through `Ecosystem::generate_hover`/`generate_diagnostics`/`generate_completions`). `Version::published_at() -> Option<PublishTime>` is a new default (`None`) trait method, purely additive; `impl_version!` gained a second macro arm accepting an optional `published_at` field. A future publish timestamp (clock skew) clamps age to 0 and counts as within cooldown, rather than suppressing the signal. The cooldown callout itself (flagging a still-cooling-down "latest" as such) is deferred to the follow-up PR — this PR ships the age display only.
- **deps-lsp**: `FreshnessConfig` (`freshness.enabled`, default `true`; `freshness.cooldown_secs`, default `259200`/3 days, clamped to 0..=30 days with a `tracing::warn!` on clamp) added to `DepsConfig`, following the existing `CacheConfig` pattern. Read once at `initialize`; live-reload via `workspace/didChangeConfiguration` is deferred to the follow-up PR. `CompletionOptions` now declares `completion_item.label_details_support: true` so LSP-conformant clients render the age suffix on completion items.
- **deps-cargo**: `CargoVersion` now carries `published_at: Option<PublishTime>`, parsed from the sparse index's `pubtime` field (already present on the wire, zero added network cost) — 100% coverage on crates.io as of 2026-08, degrading to `None` on older entries or an unparseable timestamp.
- **Breaking (pre-1.0, public API)**: `deps-pypi`'s `PypiVersion` gained `published_at: Option<PublishTime>`, replacing nothing (new field on an existing struct) but requiring every construction site to add it. Parsed from PEP 700's per-file `upload-time` in the already-requested Simple API JSON (zero added network cost): a version's `published_at` is the **maximum** `upload-time` across its release files, since PyPI allows adding a new file (e.g. a wheel) to an already-published version — the most-recently-added file is what should count for freshness (fail-closed against the cooldown window), not the version's original release.
- **Breaking (pre-1.0, public API)**: `deps-composer`'s `ComposerVersion` gained `published_at: Option<PublishTime>`, parsed from the Packagist v2 API's per-entry `time` field (already present on the wire, zero added network cost). Unlike `version_normalized`/`abandoned`, `time` is **not** inherited through the API's minified-entry field-inheritance scheme — an entry with no `time` yields `None` for that entry, never the previous entry's value, since a missing `time` means the release itself has no known publish date.
- **Breaking (pre-1.0, public API)**: `deps-bundler`'s `BundlerVersion.created_at: Option<String>` is replaced by `published_at: Option<PublishTime>`, parsed eagerly from the rubygems.org API's `created_at` field it was already carrying unparsed.
- **Breaking (pre-1.0, public API)**: `deps-dart`'s `DartVersion.published: Option<String>` is replaced by `published_at: Option<PublishTime>`, parsed eagerly from pub.dev's `published` field it was already carrying unparsed.
- **Breaking (pre-1.0, public API)**: `deps-go`'s `GoVersion.time: Option<String>` is replaced by `published_at: Option<PublishTime>`, parsed eagerly from the Go module proxy's `/@latest` and `/@v/{version}.info` endpoints' `Time` field. `/@v/list` (used by `get_versions`) carries no per-version dates, so versions from that path always have `published_at: None` — a documented Go-specific partial-coverage limitation, not a bug.
- **deps-core**: `HttpCache` now enforces a `MAX_CACHE_BYTES` (64 MiB) budget on total cached response bytes, in addition to the existing `MAX_CACHE_ENTRIES` (1000) count limit. Previously, eviction was purely count-based: since a single cached response can be as large as `MAX_RESPONSE_BYTES` (32 MiB), a cache full of near-cap entries could retain tens of gigabytes even though real registry payloads are typically well under 1 MB (CWE-400, defense-in-depth). `HttpCache::evict_entries` now also evicts oldest-first until the byte budget is satisfied, independently of the count-based eviction batch, so a cache dominated by a few large responses is trimmed without needing to hit the entry-count threshold. A new per-entry admission cap, `MAX_CACHEABLE_ENTRY_BYTES` (8 MiB, `MAX_CACHE_BYTES / 8`), keeps any single response from claiming more than 1/8 of the budget — without it, two max-size (32 MiB) responses could saturate the entire 64 MiB budget and evict the whole small-payload working set; a response over the cap is still returned to the caller, just not retained in the cache. The byte budget is a best-effort bound, not an exact guarantee under concurrent load — it is only rechecked once per request, so several requests already in flight when the budget is crossed can each still insert before the next check fires (bounded per request by the 8 MiB admission cap rather than the old 32 MiB response cap). New `HttpCache::total_bytes()` accessor exposes the running total (resolves #142).
- **deps-core**: `PackageName` and `VersionReq` newtypes (`crates/deps-core/src/package.rs`), wrapping `String`. Follow-up to #119/#121: gives package names and version-requirement strings distinct types at compile time, so a function taking one can no longer accidentally be called with the other — no new validation or normalization is added, both types accept any `String` unchanged (including the empty string), matching prior behavior exactly.

- **deps-core**: `EcosystemFormatter::validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName>` — a new defaulted hook (default: always `Ok(())`) for linting a manifest-declared package name against ecosystem-specific naming rules. Not a construction gate: `PackageName::new` remains infallible. `deps-npm`'s `NpmFormatter` overrides it with npm's real `validate-npm-package-name` rules (per-segment `encodeURIComponent(segment) == segment` check against npm's unreserved character set, leading `.`/`_` on the full name, `node_modules`/`favicon.ico` blocklist, 214-character limit, scoped-name `@scope/name` structure); uppercase names are deliberately still accepted, since npm only warns on those for legacy packages. `lsp_helpers::generate_diagnostics_from_cache`/`generate_diagnostics` now select between "Invalid package name" and "Unknown package" diagnostics based on this check when a name fails to resolve against the registry, instead of always reporting "Unknown package" (resolves #192).
- **deps-core**: vulnerability-aware code actions — a one-click "Update to `<version>` (fixes `<ADVISORY-ID>`[ +N more])" quickfix on a dependency flagged by the OSV scan, naming only the worst-severity advisory id and summarizing the rest so the title stays readable in an editor's code-action menu (the full id list still travels via `CodeAction::data` for the diagnostics binding below). `Ecosystem::generate_code_actions` and `lsp_helpers::generate_code_actions` now take the same `VersionData` (carrying `vulnerabilities`) that `generate_hover`/`generate_diagnostics_from_cache` already do (resolves #216). New `DependencyVulnerabilities::recommended_fix() -> Option<FixRecommendation>` (`crates/deps-core/src/osv/types.rs`) first determines which advisory ids are actually claimable — every advisory with a known fix, minus any id phase B ([`UpgradeStatus::CandidateVulnerable`]) still reports as applying, since claiming a fix for those would be false — and only then picks the lowest version that resolves everything in that claimed set, so an excluded advisory's own (possibly much higher) fix version can never inflate the recommendation. New `EcosystemFormatter::osv_version_to_native` hook (default: identity) converts an OSV-namespace version into the ecosystem's own namespace before it is used in a `TextEdit` or a registry lookup — `deps-go` overrides it to add the `v` prefix OSV's `fixed` field never carries (Go's mirror-direction bug, phase A sending the `v`-prefixed version to OSV, which expects it unprefixed, is tracked separately as #228 and intentionally untouched here, so this override cannot yet be exercised end-to-end). The action is built before the registry fetch so a registry outage never suppresses it (mirroring the existing FR-007 rule); when the fetch does succeed, a fix target the registry reports as yanked is dropped rather than offered, and a fix target whose text — built via `EcosystemFormatter::format_version_replacing` (see below), the same formatting the plain "update version" action below it uses, not the bare version — already matches the manifest's declared requirement is skipped as a no-op edit (e.g. `deps-dart`'s `^`-prefix wrap, or a `deps-pypi` dependency already pinned to exactly the fixed version). When the OSV scan target was the lockfile-resolved version rather than the declared requirement, the title gets an "; update lockfile to apply" suffix, since rewriting the manifest alone would not clear the diagnostic in that case. `deps-lsp`'s `handlers::code_actions` now also binds the fix action to the matching client-supplied diagnostics — `deps-core` stashes the resolved advisory ids on `CodeAction::data`, and the handler moves the `CodeActionContext.diagnostics` entries whose `source`/`code` match into `CodeAction::diagnostics` (clearing `data` once consumed) — so editors surface the action from the advisory's own lightbulb, and now honors `CodeActionParams.context.only`, filtering the returned actions by LSP's hierarchical kind matching (a request for `refactor` also matches `refactor.extract`) instead of returning every action regardless of the requested kind. Also threads the new `content: &str` manifest-source parameter (added alongside `requirements.txt` support below) through the same signature: the literal-span safety guard runs first, before either the plain "update version" action or this fix action can write a `TextEdit`, since a rejection there means no edit of either kind is safe at that range.
- **deps-pypi**: `requirements.txt`/`constraints.txt` support (pip's requirements file format). A new `parser::requirements` line-oriented parser reuses the same shared PEP 508 machinery as the existing `pyproject.toml` parser, so hover, diagnostics, markers and extras render identically across both manifest shapes. Handles comments (`#`, matching pip's whitespace-aware cut rule), blank lines, line continuations (`\`), per-requirement options (`--hash=...`, suppressing the "update version" action), recognized pip options in both `--opt value` and `--opt=value` spellings (`-r`/`-c`/`-e`/`-i`/`-f`/`--index-url`/`--pre`/`--no-index`/etc., not followed), bare URL/path/archive requirements (skipped, not parsed), and PEP 508 direct references (`name @ url`, kept). Routed via a new third `deps_core::Ecosystem::manifest_patterns` filename-pattern stage in `EcosystemRegistry::get_for_filename` (`requirements*.txt`, `*-requirements.txt`, `*.requirements.txt`, `constraints*.txt`), consulted between exact-filename and extension routing, with deterministic most-specific-wins resolution on overlap. Since `.txt` pattern-routing can claim a file the user never intended as a manifest, a content gate keeps a prose file that happens to match the pattern (e.g. `product-requirements.txt`) from producing spurious network requests and "Unknown package" diagnostics: dependencies are kept only when the file shows a "strong signal" — a recognized option, or a successfully parsed line whose dependency carries a version requirement or a Git/URL source — or more lines parsed than failed. The signal is read off the parsed dependency rather than scanned from the raw line text, so an operator- or `@`-looking substring inside an ordinary sentence (an email address, a stray comparison) cannot fool the gate into keeping prose (resolves #203).
- **deps-core**: `LineOffsetTable::line_start` accessor for a line's absolute byte offset, correct for LF/CRLF/mixed endings — required by the new requirements.txt parser, since hand-rolled cursor arithmetic under-counts CRLF lines by one byte. `byte_offset_to_position` now clamps a non-char-boundary offset down to the nearest boundary instead of panicking, reachable now that a caller (the requirements.txt parser) derives offsets by hand rather than from toml-span's boundary-safe spans.
- **deps-core**: `EcosystemFormatter::format_version_replacing(version, current)` — a new defaulted trait method (default: delegates to `format_version_for_text_edit`, unchanged behavior for every ecosystem but PyPI) for "update version" code actions that preserves the declared requirement's operator/pin style. `PypiFormatter` overrides it so `django==5.0.1` updates to `django==5.1.0` rather than the previous unconditional `django>=5.1.0,<6` — significant for `requirements.txt`, where `==` pinning (often `pip-compile`-generated) is the dominant idiom. The vulnerability-fix quickfix above uses the same method for its `TextEdit` (and its own no-op-edit guard), so a one-click fix on a `==`-pinned PyPI dependency preserves the pin instead of expanding it to a range. For `~=X.Y` and `==X.Y.*`-style pins, truncating the fix version back down to the pin's own precision can reproduce the declared text byte-for-byte even though the pin still admits the vulnerable range it started from (e.g. `~=1.0` and `==1.0.*` both still match `1.0.0`/`1.0.1`); `format_version_replacing` falls back to the untruncated exact version (`~=1.0.2`) — or, for the wildcard case, an exact pin (`==1.0.2`) — instead of silently reproducing a no-op that the guard would then skip, dropping the quickfix entirely for a still-live finding.

### Fixed
- **deps-core**: `HttpCache::evict_entries`'s pre-existing count-based eviction had an inverted `BinaryHeap<Reverse<_>>` comparison — `peek()` returns the oldest candidate, but the old code treated it as the newest-of-the-oldest-seen-so-far and only replaced it when a still-older one showed up, backwards from the intent. It evicted roughly the first ~100 entries in `DashMap` hash-iteration order with one churning slot, not the 100 oldest entries as the code and docs claimed. Fixed as part of extending eviction for the new byte budget above; eviction is now genuinely oldest-first for both the count- and byte-based paths.
- **deps-pypi**: restored the `features()` mapping (`PypiDependency::extras`) on the `deps_core::Dependency` implementation, lost when the legacy `DependencyInfo` trait was deleted (see below) — the deleted trait's impl mapped `features() -> &self.extras`, but the surviving `Dependency` impl had no `features()` override and silently fell back to the default `&[]`. Not a runtime regression (nothing dispatched through the deleted trait in production), but it erased a mapping every other feature-bearing ecosystem (e.g. Cargo) still wires up correctly.
- **deps-pypi**: dotted package names declared as Poetry table keys (e.g. `[tool.poetry.dependencies] "zope.interface" = "^5.0"`) failed to match their lockfile entries — hover showed no **Current** version and a spurious "Unknown package" warning was emitted. `pep508_rs::PackageName` already PEP 503-normalizes at construction, so this affected only the Poetry table-key path, where the name is taken verbatim from the TOML key. Fixed by replacing the ad-hoc `-`→`_` normalizer with one canonical PEP 503 normalizer (`deps_pypi::name::normalize`, lowercase + `-`/`_`/`.` collapsed to `-`), now used uniformly by the formatter, registry, and lock file parser (resolves #212).
- **deps-core**: `generate_code_actions`'s "update version" code action wrote its `TextEdit` unconditionally, unlike the bulk "update all" path (`collect_update_all_edits`), which already guards against rewriting a `version_range` that no longer slices to its declared requirement text. Also fixed `deps-pypi`'s `start_offset` computation (used to locate the version specifier within a PEP 508 requirement string): it was derived from the pep508-normalized name and rejoined extras rather than scanning the raw source text, so it pointed the range at the wrong bytes for spaced extras (`flask [async] >= 3.0`) or a dotted/underscored source name (`my__pkg==1.0`) — accepting the code action on either could corrupt the file. Both fixes matter more for `requirements.txt`, where spaced extras and pinned versions are common.
- **deps-maven**: `version_satisfies_requirement` now parses Maven's bracket-interval range syntax (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`) and top-level comma unions (`(,1.0),(1.2,)`) instead of comparing the requirement string for plain equality, so dependencies pinned to a range no longer show a permanently "outdated" hover/diagnostic. Added `crates/deps-maven/src/range.rs`; bounds are compared with the qualifier-aware `deps_maven::interval`/`compare_versions_for_range`, so `[1.0-beta,2.0-rc)`-style bounds order correctly. Malformed input (unbalanced/stray brackets, an extra comma-separated component, a mismatched no-comma pin like `[1.0)`, or any unparseable member of a union) fails closed — the whole requirement is rejected (`false`) instead of silently matching on the well-formed remainder (resolves #172).
- **deps-gradle**: `version_satisfies_requirement` now handles dynamic versions (`1.0+`, `2.10.+`), `latest.release`/`latest.integration` selectors, and the same bracket-interval range syntax as Maven (plus Gradle's own reversed-bracket exclusive notation, `]1.2,1.5]`/`[1.1,2.0[`), instead of plain string equality. Added `crates/deps-gradle/src/range.rs`, reusing `deps_maven::interval`'s `compare_versions_for_range` for bound comparisons. Since Gradle has no comma-union syntax, a union-shaped string (e.g. `[1.0,2.0),[3.0,4.0)`) is rejected outright rather than parsed as one interval with a corrupted bound; the same malformed-input fail-closed rules as Maven apply otherwise (resolves #172).
- **deps-gradle**: `GradleFormatter::version_satisfies_requirement` had no guard for an unresolved Gradle variable reference (bare `$var` or braced `${var}`) in a dependency's version requirement, unlike `deps-maven`'s existing `${property}` guard — an unresolved variable produced a spurious "Newer version available" diagnostic/inlay hint instead of being skipped. A requirement containing `$` is now treated as satisfied, matching Maven's behavior (resolves #183).
- **deps-core**: `EcosystemFormatter::is_requirement_up_to_date`'s boolean result was overloaded — Maven/Gradle's `${property}`/`$var` unresolved-variable guards (added for #183) return `true` to suppress a false "outdated" diagnostic, but `generate_inlay_hints` read that same `true` as "confirmed up to date" and rendered an up-to-date badge for a requirement the server never actually verified (`deps-lsp`'s inlay-hints handler hardcodes `show_up_to_date_hints: true`). Added a tri-state `RequirementStatus` (`UpToDate`/`Outdated`/`Unresolved`) plus `EcosystemFormatter::{requirement_is_unresolved, requirement_status}`, and switched `generate_inlay_hints`/`generate_diagnostics_from_cache`/`generate_diagnostics` to it: diagnostics still suppress on `Unresolved` (same behavior as before), but inlay hints now skip the hint entirely on `Unresolved` instead of showing "up to date" (resolves #189).
- **deps-gradle**: a version-catalog dependency whose `version.ref` alias was missing from `[versions]` (or pointed at a Gradle rich-version table rather than a plain string) parsed to a `None` requirement; generic `deps-core` diagnostic/inlay-hint code turned that into an empty string via `unwrap_or("")`, which then always compared as outdated — a "Newer version available" hint/diagnostic for a version the server was never able to resolve in the first place. `generate_inlay_hints`/`generate_diagnostics_from_cache` now treat a `None` requirement (paired with a populated `version_range`) as `RequirementStatus::Unresolved` directly, rather than falling through to the empty-string comparison; `GradleFormatter` also now treats an explicit empty catalog entry (`[versions] foo = ""`) as unresolved for the same reason (resolves #190).
- **deps-maven**: range/interval bound matching (`crates/deps-maven/src/interval.rs`) now normalizes a missing trailing version segment as equal to a zero-valued one, matching Maven's own `IntItem.compareTo(null)` rule (already used one level down for qualifier tokens), via a new `compare_versions_for_range` comparator. Previously `1.0` compared less than `1.0.0` because the missing third segment was treated as an empty qualifier, which always loses to a numeric segment — so a range bound with fewer or more segments than the version being checked (e.g. `[4.0,4.1]` vs `4.1.0`, or `[4.1.0,4.2]` vs `4.1`) could wrongly reject a version that Maven itself considers in range. The general-purpose `compare_versions` (used by `crates/deps-maven/src/registry.rs`'s version-list `sort_by`) is deliberately left untouched — treating a missing segment as zero there breaks the total order `sort_by` requires, since the same missing/zero segment can rank differently against a same-base qualifier depending on which version supplies it (resolves #182).
- **deps-gradle**: `version_satisfies_requirement` no longer panics on a single-character range requirement (`"["` or `"]"`). Gradle's reversed-bracket notation makes `[` and `]` valid both as an opener and as a closer, so a one-character requirement previously sliced its inner bounds with a start index past the end index; the shared interval parser now rejects any requirement shorter than its two delimiters as malformed instead of slicing (resolves #187).
- **deps-lsp**: content received via `textDocument/didOpen`/`didChange` had no size bound before reaching `ecosystem.parse_manifest`, unlike disk-loaded documents (cold start), which were already capped at `MAX_FILE_SIZE` (10MB) in `document::loader`. `document::lifecycle::{handle_document_open, handle_document_change}` now reject content over the same 10MB limit before parsing; the rejected content is never stored or parsed. Both `Backend::handle_open` and `Backend::handle_change` (`server.rs`) now surface the rejection to the client via `window/logMessage` (previously `handle_change`'s error arm only logged server-side via `tracing::error!`, so a rejected `didChange` left the client editing against a stale server-side document with no client-visible signal that the edit was never applied) (resolves #161).
- **deps-lsp**/**deps-maven**: Maven completion inserted `<artifactId>{name}</artifactId>...` where `name` was the registry's synthesized `group:artifact` identifier, producing a malformed dependency block with no `<groupId>` element and a bogus `<artifactId>` value. This affected two separate code paths: the LSP-level text fallback used on a blank line inside `<dependencies>` (`create_package_completion_item` in `deps-lsp`, now splits the name on the first `:` and emits a separate `<groupId>` element, falling back to the previous single-element form only if the name has no `:`), and the primary parse-result-based path used when the cursor is already inside a `<groupId>`/`<artifactId>` tag (`MavenEcosystem::generate_completions` in `deps-maven`, which previously inserted the full `group:artifact` string into whichever single tag the cursor was in via the generic `build_package_completion`). The primary path now uses a new field-aware `complete_package_names_for_field`/`build_field_completion`, inserting only the `groupId` or `artifactId` half matching the tag the cursor is in, via a proper LSP `textEdit` that replaces exactly the already-typed value span (`MavenEcosystem::detect_xml_context` now also returns that span) rather than relying on the client's own word-boundary heuristics to place a plain `insertText` — the latter mis-fires on `.`-separated `groupId`s like `org.apache.commons`, since `.` is outside most editors' default word pattern (resolves #210).
- **deps-lsp**/**deps-swift**: Swift completion inserted `.package(url: "{name}", from: "{latest}")` using the bare `owner/repo` GitHub identifier as the URL (invalid Swift Package Manager syntax) and, since search results deliberately leave `latest_version` empty to avoid N+1 GitHub API calls, an empty `from: ""` clause. As with Maven above, this affected both the fallback path (`create_package_completion_item` in `deps-lsp`, now prefers `Metadata::repository()` for the URL, falling back to `https://github.com/{name}` when absent, and omits the `from: "..."` clause entirely when the latest version is empty) and the primary path (`SwiftEcosystem::generate_completions` in `deps-swift`): completion there fires with the cursor already inside the `url: "..."` string literal of an existing `.package(...)` call, but previously inserted the bare `owner/repo` identity into that string via the generic `build_package_completion`, an invalid URL fragment. A new `build_url_completion` now always inserts the full `https://github.com/owner/repo` URL — Package.swift's only completion call site for a package name is inside a URL string, so a bare-identity insertion is never the correct shape regardless of how much of the `https://github.com` scheme the user has typed so far. `SwiftEcosystem::generate_completions` locates the dependency whose `name_range()` contains the cursor and passes that span to `build_url_completion` so a proper `textEdit` replaces the whole existing URL literal (falling back to `insertText`-only, not a guessed range, if no containing dependency is found) — without a real range, `/`/`.`/`:` sitting outside most editors' default word pattern meant a plain `insertText` only replaced the last path segment, doubling the `https://github.com/` prefix instead of completing it. The primary-path item's `detail` is also cleared instead of showing a bare `"v"` when `latest_version` is empty, matching round 1's `from:`-omission fix for the same known empty-version tradeoff (resolves #211).
- **deps-maven**: `MavenEcosystem::detect_xml_context` treated `position.character` (a UTF-16 code unit offset per the LSP spec) as a raw byte index when slicing the pom.xml line, panicking with "byte index N is not a char boundary" whenever a multi-byte character (e.g. an accented letter in an `artifactId`/`groupId`/`version` value) preceded the cursor. The cursor offset is now converted to a byte offset once via `deps_core::completion::utf16_to_byte_offset` before any slicing; the returned `LspRange`'s `character` fields are converted back to UTF-16 units via a new `deps_core::completion::byte_to_utf16_offset` (resolves #217).
- **deps-maven**: `detect_xml_context`'s returned replace range spanned only the already-typed prefix up to the cursor, so completing mid-value (e.g. `<artifactId>jun|it</artifactId>`) left the untouched tail (`it`) behind instead of being overwritten — unlike Swift's `build_url_completion`, which already replaces the full existing value. The range now spans the entire existing tag value (opening tag to `</`), matching Swift's replace semantics. Two edge cases in the widened range were caught in review: when no closing tag is found on the line, the range now falls back to the cursor position (insert-mode) instead of `line.len()`, which previously let the replace range swallow unrelated trailing line content (e.g. an XML comment); and the range's end is now clamped to never fall before the cursor, since a closing tag appearing partway between the already-typed prefix and the cursor (e.g. cursor placed inside `<`/`/` of `</artifactId>`) could otherwise produce a `textEdit.range` that does not contain the request position, violating LSP 3.17 and causing conformant clients to discard the completion item (resolves #218).
- **deps-core**/**deps-lsp**: `build_package_completion`'s markdown documentation header and `detail` field, and the sibling `create_package_completion_item` fallback path in `deps-lsp` (`detail: format!("Latest: {latest}")`), unconditionally appended `v{latest_version}`/`Latest: {latest_version}`, rendering a dangling suffix (e.g. `**apple/swift-nio** v`, `"Latest: "`) whenever a registry search result has no version (by design, for Swift's search results — see `SwiftRegistry::search`). Both code paths now omit the version suffix entirely when `latest_version` is empty; the equivalent Swift-local workaround in `build_url_completion` (`crates/deps-swift/src/ecosystem.rs`) is removed as redundant (resolves #218).
- **deps-lsp**: `server_capabilities()` advertised only `CodeActionKind::REFACTOR`, even though the #216 vulnerability-fix action emits `QUICKFIX` — combined with the new `context.only` request filtering, a client that trusts the advertised list could never request or surface the fix action. `QUICKFIX` is now advertised alongside `REFACTOR`.
- **deps-core**/**deps-go**: added `EcosystemFormatter::osv_version` — a new defaulted hook (default: identity) that rewrites a native version string into the spelling sent to OSV.dev, mirroring the existing `osv_package_name` hook for names. `deps-lsp`'s OSV scan-target builder now routes every version through it before querying OSV. `deps-go`'s `GoFormatter` overrides it to strip the mandatory `v` prefix Go module versions carry (`v1.2.3` -> `1.2.3`), matching OSV's documented SEMVER-range convention and the `osv_package_name` precedent; live-testing against the real OSV.dev API found the server currently tolerant of the `v`-prefixed spelling either way, so this alone does not reproduce the originally reported symptom — see the `resolved_versions` fix below for the confirmed root cause. `deps_core::osv::ScanTarget` gained a `display_version` field alongside `version`, so `osv_version`'s wire-format rewrite never leaks into a user-facing surface: `OsvClient::check_candidates` (and the `UpgradeStatus` it produces, rendered in hover) now uses `display_version`, keeping Go's "Latest version is also affected" hover text in native `vX.Y.Z` spelling instead of the stripped wire form.
- **deps-go**/**deps-lsp**: `build_scan_targets` (deps-lsp's OSV scan-target builder) now uses `go.mod`'s own declared version directly for Go dependencies instead of go.sum-derived `resolved_versions`, and is the confirmed root cause of #228's reported "always Clean" Go scanning: `GoSumParser::parse_go_sum`'s last-occurrence-wins parsing returns the highest version ever recorded in go.sum, not necessarily the one actually selected by Go's MVS, because `go get`/`go build` only ever append to go.sum (only `go mod tidy` prunes stale entries) and go.sum is written sorted ascending by semver — so a stale, no-longer-selected higher version left over from a downgrade always sorts last and silently overrides the manifest's correct pinned version in the OSV query. Unlike Cargo/npm, where the manifest is a range and the lockfile holds the pin, Go's `go.mod` `require` line is already an exact pinned version, so it is authoritative for Go and does not need go.sum's checksum ledger to resolve a query version (resolves #228).
- **deps-core**/**deps-lsp**: `DiagnosticsConfig`'s `outdated_severity`/`unknown_severity` fields were parsed from user configuration but never read, so setting them had no effect. New `deps_core::DiagnosticSeverities` DTO (mirroring the existing `FreshnessSettings` pattern) is threaded through `Ecosystem::generate_diagnostics`/`lsp_helpers::{generate_diagnostics_from_cache, generate_diagnostics}`, replacing the hardcoded `WARNING`/`HINT` severities on the "Unknown package" and "Newer version available" diagnostics with the configured values on the live LSP path (resolves #224). `yanked_severity` is also parsed and threaded through the same `DiagnosticSeverities` DTO, but is only honored by `lsp_helpers::generate_diagnostics` — a registry-calling public `deps-core` API with no callers in this workspace — not by `generate_diagnostics_from_cache`, the function `deps-lsp` actually runs; wiring a real yanked diagnostic into the live cache path needs `Registry::get_versions` instead of the always-non-yanked `get_latest_matching` result the cache is built from, and is tracked separately (#233).
- **deps-core**/**deps-go**/**deps-lsp**: the go.sum staleness behind #228 also reached hover, diagnostics, and inlay hints, beyond the OSV-scan path #228 fixed — a stale, no-longer-selected higher version left over from a downgrade can still be recorded in go.sum (only `go mod tidy` prunes it) and, since go.sum sorts ascending by semver, always sorts last and wins naive last-occurrence-wins parsing. New `EcosystemFormatter::manifest_requirement_is_resolved_version(dep)` hook (default `false`) marks an ecosystem where the manifest's declared requirement is itself already the exact resolved version, rather than a range; `GoFormatter` returns `true` only for a `require`-directive dependency (`exclude`/`replace` pseudo-dependencies are excluded, since their `version_requirement()` is not an in-use version). `generate_inlay_hints`/`generate_hover` prefer `dep.version_requirement()` over the go.sum-derived `resolved_versions` entry when the hook reports `true`; `handle_document_open`'s resolved-versions-as-instant-cached-placeholder seeding is filtered the same way, since seeding the stale value there could otherwise desync the "latest" comparison operand against the now-corrected resolved value during the cold-open window before the registry fetch completes. `build_scan_targets`'s `EcosystemId::Go` special case (added by #228) is unified onto this same hook. Known accepted trade-offs, deliberately not addressed here: a Go dependency with no cached registry data yet and no go.sum entry now renders an unverified "up to date" badge off the go.mod pin alone; and the up-to-date comparison for a `require` dependency uses exact string equality rather than `GoFormatter`'s `+incompatible`-tolerant matcher (low-impact, since Go itself writes `+incompatible` into go.mod) (resolves #235).
- **deps-core**/**deps-cargo, deps-npm, deps-pypi, deps-dart, deps-bundler, deps-composer, deps-nuget, deps-gradle**: package-name completion's `textEdit.range` was hardcoded to `Range::default()` (`(0,0)-(0,0)`) for every ecosystem going through the shared `complete_package_names_generic` path, unlike Maven/Swift's already-real ranges (#218 above) — a conformant LSP client applies the edit at the top of the manifest instead of at the cursor. `CompletionContext::PackageName` now carries a `range: Range` field (the dependency's full `name_range()`, populated by `detect_completion_context`), and `complete_package_names_generic` takes that range as a new `insert_range` parameter instead of manufacturing a placeholder; all seven affected ecosystems thread it from `CompletionContext` through their `complete_package_names` helper. `position_in_range` tolerates a request position one column past `name_range.end` (a convenience for firing completion right after the last typed character), but `detect_completion_context`'s `PackageName` branch now requires *strict* containment (`position.character <= name_range.end.character`) rather than reusing that tolerance to decide whether the range should apply — an earlier version of this fix instead widened `name_range` to cover that extra column, but the text immediately following a name is frequently structurally significant (a closing quote, the space before `=`), so widening the range let a client's applied edit delete it (e.g. `"axios"` with the cursor one past the name lost its closing quote). A one-past-end position now falls through without matching this dependency's name at all instead of matching with a corrupting range; the on-boundary case (cursor exactly at `name_range.end`) already matches correctly with the unwidened range, so nothing is lost. Gradle does not go through `detect_completion_context` (it has its own text-scanning `detect_catalog_context`/`detect_dsl_context` for `libs.versions.toml` and Kotlin/Groovy DSL files) — both now also compute and return the real span of the existing `module`/`group:artifact` value, mirroring Maven's `detect_xml_context` convention of replacing the whole existing value rather than just the already-typed prefix. Both Gradle functions convert `position.character` (a UTF-16 code unit offset per the LSP spec) to a byte offset once via `deps_core::completion::utf16_to_byte_offset` before slicing (previously a raw cast, panicking on multi-byte content, and separately emitting byte offsets directly as UTF-16 positions in the returned range); `detect_catalog_context`'s `module`/`version` branches now also require an odd quote count before the cursor (mirroring `detect_dsl_context`'s existing `in_string` parity check) — without it, a cursor placed after an already-closed value on the same line (e.g. a trailing comment) misidentified the closing quote as the opening one and returned a bogus "package" context. Both branches also now scope their keyword/quote-parity search to the current inline-table field (the segment after the last unquoted comma, via a new `current_field_start` helper) instead of the whole line — an inline-table catalog entry with multiple fields on one line (e.g. `lib = { version = "1.0", module = "com.exa` with the cursor inside the still-open `module` value) could otherwise `rfind` past the comma onto an earlier field's keyword/quote and return the wrong context type (resolves #232).

### Security
- **deps-core**: `Advisory::fixed_versions` was stored verbatim from the OSV wire record with no character or length validation, and — since #216 — flows into a manifest `TextEdit.new_text` written by an `is_preferred: true` quickfix. A `fixed` value containing manifest-breakout characters (`"`, `,`, a newline) could escape the version string literal it replaces (e.g. injecting a `git = "https://evil/..."` key into `Cargo.toml`, or a `scripts.postinstall` entry into `package.json`) from a single compromised or malformed upstream advisory record plus one user click. `OsvVulnRecord::into_advisory` now validates each `fixed` event against a permissive but bounded character set (`[A-Za-z0-9.+_~:*^-]`, non-empty, capped at 64 bytes) before it reaches `Advisory::fixed_versions`, dropping and logging any entry that fails — mirroring the existing `is_valid_osv_id` chokepoint for the advisory id field, which also gained a 128-byte length cap (previously alphabet-only, allowing an unbounded id to ride along into `Diagnostic.code`, hover markdown, and now a `CodeAction` title).

### Changed
- **Breaking (pre-1.0, internal API)**: `Ecosystem::{generate_hover, generate_diagnostics, generate_completions}` and `lsp_helpers::{generate_hover, generate_diagnostics_from_cache, generate_diagnostics}` now take an additional `deps_core::FreshnessSettings` parameter (issue #145, PR1 of 2). All call sites across the workspace pass it through. `generate_hover` and `generate_completions` (via `completion::{build_version_completion, complete_versions_generic}`) read `freshness.enabled` to gate the age-suffix rendering described above; the diagnostics functions still ignore the parameter — diagnostics carry no freshness-based rendering in this PR.
- **Breaking (pre-1.0, internal API)**: `Ecosystem::generate_diagnostics` and `lsp_helpers::{generate_diagnostics_from_cache, generate_diagnostics}` now take an additional `deps_core::DiagnosticSeverities` parameter (issue #224). All call sites across the workspace pass it through.
- **deps-maven, deps-gradle**: unified the single-interval range-parsing logic between the two crates into `deps_maven::interval` (`VersionRange`, `BracketStyle`, `parse_interval`, `contains`), which `deps-maven`'s union-splitting `satisfies` and `deps-gradle`'s `satisfies` both now delegate to, selecting Gradle's reversed-bracket notation via `BracketStyle::AllowReversed`. Previously the two crates carried byte-identical parser bodies apart from their delimiter tables (resolves #184).
- **deps-lsp**: `DocumentState::ecosystem_id: &'static str` is now a method (`ecosystem_id()`) instead of a stored field, since it was always fully derived from `ecosystem: EcosystemId` — removes the possibility of the two falling out of sync. `handlers::completion::fallback_completion` now takes the already-typed `EcosystemId` instead of re-parsing it from the `&str` id (resolves #155).
- Converted `PypiRegistry::search`, `GoEcosystem::complete_package_names`, `GoEcosystem::complete_features`, and `Backend::shutdown` from `async fn` to `fn` returning `impl Future` directly, satisfying clippy's `unused_async_trait_impl` lint (no `.await` in any of these bodies); behavior is unchanged
- **deps-pypi**: canonical package-name normalization is now PEP 503 (lowercase, `-`/`_`/`.` collapsed to `-`) everywhere — registry lookups, `PypiFormatter::normalize_package_name`, and lock file parsing. The historical `-`→`_` lockfile/formatter key space is deleted outright (pre-1.0, no compat shim); `poetry.lock`/`uv.lock` entries are now looked up by hyphenated key.
- **deps-core**: `Ecosystem::generate_code_actions` gained a `content: &str` parameter (needed for the literal-span guard fixed above). Updates the trait's default implementation, `lsp_helpers::generate_code_actions`, the `deps-lsp` `handlers::code_actions` handler, and the 3 ecosystem crates with direct test call sites (`deps-go`, `deps-npm`, `deps-pypi`).
- **Breaking (pre-1.0, internal API)**: `deps_core::ecosystem::Dependency::name`/`version_requirement` now return `&PackageName`/`Option<&VersionReq>` instead of `&str`/`Option<&str>`. All 11 ecosystem crates' dependency structs (`ParsedDependency`, `PypiDependency`, `GoDependency`, `BundlerDependency`, `DartDependency`, `MavenDependency`, `GradleDependency`, `SwiftDependency`, `NuGetDependency`, `ComposerDependency`, `NpmDependency`) retype their `name`/version-requirement fields to match. The `VersionData`/`DependencyDiff`/`fetch_latest_versions_parallel` caches (`HashMap<String, ...>` at the time) were deliberately left out of scope here — see the follow-up entry below, which rekeys them too.
- **Breaking (pre-1.0, internal API)**: completes the previous entry's deferred rekey — `deps_core::VersionData::{cached, resolved}`, `deps_lsp::document::DocumentState::{cached_versions, resolved_versions}` (and their `update_*` setters), and the internal `DependencyDiff`/`FetchResult`/`fetch_latest_versions_parallel` caches in `deps-lsp` now use `HashMap<PackageName, String>`/`Vec<PackageName>`/`HashSet<PackageName>` instead of `String`-keyed collections. `VersionData` is reachable through the public `Ecosystem` trait (`generate_inlay_hints`/`generate_hover`/`generate_diagnostics`), so this breaks any external `Ecosystem` implementor passing `HashMap<String, String>`. `PackageName` gains `impl Borrow<str>`, so `&str` still works for lookups into these maps (`map.get("serde")`); the `Registry` trait and the lockfile-backed `ResolvedPackages` stay `String`-keyed, converted at the boundaries where they cross into LSP state (`load_resolved_versions`, `Backend`'s lock-file-change handler) — the `get_latest_matching` boundary conversion this entry originally introduced was removed by the entry below, which retypes `Registry` to accept `&PackageName` directly (resolves #193).
- **Breaking (pre-1.0, internal API)**: follow-up to the above — `deps_core::Registry::{get_versions, get_latest_matching, package_url}` now take `&PackageName` for the package-name parameter, and `get_latest_matching`'s `req` parameter additionally takes `&VersionReq`, instead of `&str`; `Registry::search` is unchanged, as its argument is a query fragment rather than a package name. `deps_core::lsp_helpers::EcosystemFormatter::{normalize_package_name, package_url}` take `&PackageName`, and `{is_requirement_up_to_date, requirement_is_unresolved, requirement_status}` take `&VersionReq`; `version_satisfies_requirement` and `format_version_for_text_edit` remain `&str`, as they operate on decomposed constraint fragments and concrete versions respectively, neither of which has a newtype. `deps_core::Metadata::name` returns `&PackageName` — this is the registry-reported identifier and is not guaranteed byte-identical to the manifest-declared `Dependency::name()` (casing may differ; Maven/Gradle synthesize a `"group:artifact"` value). `CompletionContext`'s `package_name` fields and `deps_core::completion::complete_versions_generic`'s `package_name` parameter take `PackageName`; `complete_package_names_generic`'s `prefix` remains `&str`, as it is a user-typed search fragment, not a package name. Package-name-keyed caches (`VersionData`, `DocumentState`'s `cached_versions`/`resolved_versions`) are already `HashMap<PackageName, _>` per the rekey above; `ResolvedPackages` (lockfile-backed) stays `String`-keyed (resolves #194).

### Removed
- Removed unused `async-trait` workspace dependency from root `Cargo.toml` and 10 crate manifests (never invoked via `#[async_trait]`; native async traits used throughout) (#159)
- **deps-gradle**: deleted the dead `GradleError::InvalidDependency`, `GradleError::Maven`, and `GradleError::Io` variants (with their `#[from]` conversions and the reverse `impl From<DepsError> for GradleError`) — none was ever constructed outside `error.rs`'s own tests; the crate only ever produces `GradleError::ParseError`, and no call site in the crate propagates an `io::Error` or `MavenError` via `?` into a `GradleError`-returning function (resolves #171).
- **Breaking (pre-1.0, internal API)**: deleted the legacy `deps_core::parser::{DependencyInfo, ManifestParser, ParseResultInfo}` traits, dead since the `ecosystem::{Dependency, ParseResult}` migration — no production code called them through the trait interface anywhere in the workspace (only test-only `use` statements and the `impl_dependency!` macro's now-removed `DependencyInfo` half exercised them). Every ecosystem dependency struct across all 11 crates already implemented `ecosystem::Dependency` in parallel with near-identical method bodies (see the PyPI `features()` fix above for the one exception), so callers migrate by depending on `ecosystem::Dependency`/`ecosystem::ParseResult` (already re-exported as `deps_core::Dependency`/`deps_core::ParseResult`) instead (resolves #139).
- **Breaking (pre-1.0, public API)**: removed the unused `serde::Serialize` derive from `deps-go`'s `GoDependency`, `GoParseResult`, and `GoDirective` — dead code, since nothing in the workspace ever serialized these types (resolves #195).

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

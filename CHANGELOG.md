# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **deps-core**: new ungated `edit` module (`ManifestEdit`, `PlannedUpdate`, `EditSpan`, `UpdateKind`/`classify_update`, `collect_update_edits`, `plan_vulnerability_fix`) shared by `deps-lsp`'s code-lens/code-action edit planning and the new `deps-cli update` subcommand (resolves #1329) (#1343)
- **deps-core**: new `fs_probe::write_atomic` — symlink-refusing, permission-preserving atomic file write (resolves #1329) (#1343)
- **deps-cli**: new `update` subcommand plans and writes back version-requirement edits for one manifest's outdated (default mode) or OSV-vulnerable (`--security-only`) dependencies, with `--package` selection, `[update].ignore` rules (honored only via explicit `--config`), `--dry-run`, and `table`/`json` output (resolves #1115, #1119, #1120) (#1343)
- **ci**: new weekly/manual `live-registry-tests` workflow runs the workspace's `#[ignore]`d, network-gated tests with a real `GITHUB_TOKEN`, non-blocking for PRs (#1297)
- **deps-core**: new `completion::build_completion_sort_text`/`starts_with_ascii_case_insensitive` helpers computing exact-prefix-tiered `sort_text`, shared by deps-maven and deps-swift's field/url completion overrides (resolves #1282) (#1293)
- **deps-core**: new `is_safe_feature_name` allowlist predicate, gating Cargo feature-completion names (resolves #1296)
- **deps-core**: new `lsp_helpers::HoverMarkdown` typed builder replaces `generate_hover`'s bare `&mut String` accumulator, structurally enforcing per-field-kind length caps and escaping instead of relying on call-site discipline (resolves #1310) (#1322)
- **deps-lsp** (test infrastructure): new `server.rs` test-only helpers capture outgoing `window/showMessage` notifications via `LspService`'s loopback `ClientSocket`, closing the `executeCommand` `updateAllOutdated`/`pinAllToSha` URI-canonicalization coverage gap left open by #1198; no runtime behavior change (resolves #1199) (#1334)
- **deps-lsp** (test infrastructure): new test drives a real `initialize`/`applyEdit` handshake through `LspService`'s loopback socket, closing `commands::UPDATE_VERSION`'s `canonicalize_uri` coverage gap (resolves #1335) (#1342)
- **ci**: new native `ubuntu-24.04-arm` test leg runs `deps-core`'s test suite on real aarch64 Linux, catching Linux-arch-dependent ABI bugs that the build-only `cross-check` job never exercised (resolves #1359) (#1360)
- **deps-core**: new `unresolved_requirement_conformance!` test macro asserts an ecosystem never rewrites an unexpanded version-requirement placeholder, independent of whether `plan_vulnerability_fix`'s gate happens to short-circuit it first (resolves #1354) (#1367)
- **deps-core**: `unresolved_requirement_conformance!` gains a `formatter_guarded` arm for ecosystems whose placeholder syntax can't be expressed by the existing `reachable`/`no_placeholder_syntax` arms; **deps-gitlab-ci** switches onto it and **deps-maven**/**deps-gradle** gain their first invocations of the macro, replacing hand-written `MockDep`-based tests (resolves #1372) (#1376)
- **deps-lsp** (test infrastructure): new test drives a real `initialize`/`applyEdit` handshake through `LspService`'s loopback socket against an unanswered client, closing `apply_batch_edit`'s `CLIENT_REFRESH_TIMEOUT` real-timer coverage gap left open since #1381 removed the command that used to exercise it; no runtime behavior change (resolves #1382) (#1387)
- **fuzz**: new `bundler_lockfile`, `go_lockfile`, `toml_lockfiles` (Cargo/PyPI), `json_lockfiles` (npm/Composer/NuGet/Swift), and `deps_cli_config` targets close the lock-file/config-parser fuzz-coverage gap (resolves #1404) (#1409)

### Security
- **deps-core**: `url_for_tracing`/`RedactedUrl` now masks additional path-token shapes missed by #1431 — GitLab CI job-token prefixes, Hugging Face tokens, base64url-shaped opaque tokens, and marker-gated long hex tokens (e.g. packagecloud `/priv/<hex>`) — while still leaving benign package names and commit SHAs unmasked (resolves #1432) (#1439)
- **deps-core**: `url_for_tracing`/`RedactedUrl` now also mask a token-shaped host label or path piece with no credential syntax of its own (e.g. `https://npm-proxy.fury.io/AbCdEf1234567890xyz/acme/`, `https://ghp_<36>.registry.example/`), closing a gap where such a value passed through unredacted into tracing/error output (resolves #1429) (#1431)
- **deps-npm**: project-tier `.npmrc` `${VAR}` registry values are now rejected fail-closed instead of being expanded from the process environment, closing an arbitrary-environment-variable exfiltration vector via a hostile repository's committed `.npmrc` (resolves #1420) (#1428)
- **deps-core**: the OSV advisory fetch bound (`MAX_ADVISORY_RECORDS`) is now decoupled from the display cap (`ADVISORY_DISPLAY_CAP`), so vulnerability-fix recommendations and quickfixes consider every fetched advisory instead of only the first 5 (resolves #1422) (#1428)
- **deps-core**: `requirement_contains_template_placeholder`'s `$(VAR)` grammar now also accepts a hyphen (`$(MOD-VERSION)`), no-oping a destructive rewrite for hyphenated MSBuild/Makefile-style placeholders instead of silently overwriting them (resolves #1421) (#1426)
- **deps-core**: `requirement_contains_template_placeholder` now also recognizes `$(VAR)` (Makefile/MSBuild-style) placeholders, no-oping a destructive rewrite instead of silently overwriting an unresolved variable reference in Cargo/npm/PyPI/Deno/Go/Dart/Maven/GitHub Actions manifests (resolves #1417) (#1419)
- **fuzz**: seed lockfiles bump vulnerable package versions flagged by Dependabot (requests, certifi, express, body-parser, phpunit/phpunit, swift-nio, puma), and `.gitattributes` marks `fuzz/seeds/` as `linguist-vendored` so GitHub's dependency graph stops treating parser-fuzzing fixtures as real project dependencies (#1414)
- **deps-bundler**: `format_version_replacing`/`compile_requirement`/`version_satisfies_requirement`/`requirement_is_unresolved` now no-op an unresolved Ruby string-interpolation placeholder (`"~> #{V}"`, plus shorthand `#@ivar`/`#@@cvar`/`#$GVAR` forms) instead of planning a destructive vulnerability-fix rewrite (resolves #1354) (#1367)
- **deps-swift**: `format_version_replacing_for`/`format_version_replacing`/`compile_requirement`/`version_satisfies_requirement`/`requirement_is_unresolved` now no-op an unresolved Swift string-interpolation placeholder (`from: "\(v)"`) instead of planning a destructive vulnerability-fix rewrite (resolves #1354) (#1367)
- **deps-gitlab-ci**: `format_version_replacing_for` now no-ops an unresolved `$VAR`/`${VAR}`/`%VAR%` GitLab CI variable reference in a `ref:`/`@version` pin instead of planning a destructive rewrite (resolves #1365) (#1368)
- **deps-core**: `fs_probe::open_no_follow` now uses `libc::O_NOFOLLOW` instead of a hand-rolled per-`target_os` constant, fixing a wrong value on aarch64/arm/powerpc Linux that silently disabled symlink refusal in no-follow reads (resolves #1348) (#1358)
- **deps-core, deps-nuget, deps-pypi**: `ResolvedPackage`/`ResolvedSource`, `ScanTarget`, `ResolvedShaPin`, `PackageSourceEntry`, and `RequirementRef` now redact credential-shaped fields in `Debug` output (resolves #1237) (#1318)
- **deps-core**: `ResolvedPackages`' `Debug` output now redacts its `HashMap` key too, closing a gap where the key duplicated the already-redacted `ResolvedPackage.name` (resolves #1319) (#1324)
- **deps-core**: `ParseError` construction and `Debug` field redaction are now enforced at compile time instead of test-time-only (resolves #1238, #1250)
- **github-action**: `action.yml` now pins the Docker image by digest instead of the mutable `:1` tag; the release workflow opens a PR repointing `action.yml` at the newly published digest on every release, for a maintainer to review and merge (resolves #1274) (#1292)
- **deps-core, deps-gitlab-ci**: hover no longer renders unbounded resolved/requirement/marker/latest/recent-version text, deprecation reason/replacement, GHA/GitLab CI's resolved tag, or a GitLab `component:` include's project-path link label, closing the same length-cap gap #1272 already closed for OSV advisory fields; name/version-shaped fields (versions, marker expressions, deprecation replacement names, git tags) are now also swept for the full invisible/bidi-override character class before rendering, closing a gap where a non-bidi Unicode format character (e.g. U+206A) survived into hover but not the equivalent diagnostic (resolves #1311) (#1322)
- **deps-core**: hover no longer renders unbounded OSV advisory `id`/`fixed`/`version`/`summary`/`aliases` text (resolves #1272) (#1298)
- **deps-core**: `completion::build_package_completion` gates a search result's `repository`/`documentation` URL through `is_safe_registry_url` before embedding it as a Markdown link destination, dropping a `javascript:`/`data:`/non-HTTPS URL instead of only backslash-escaping it; a `http://`/`git+ssh://`/`git://` repository link is now also dropped rather than rendered, since only `https://` passes the gate (resolves #1285) (#1293)
- **deps-core**: `completion::build_package_completion` now rejects the whole completion item outright when the registry-supplied `latest_version` fails `is_safe_version_string`, instead of rendering a `detail`/documentation-header field built from an unbounded or bidi-bearing value; a passing value is additionally sanitized and length-capped in both fields as defense-in-depth (resolves #1286) (#1293)
- **deps-core**: `completion::build_feature_completion` now gates registry-supplied `feature_name` through `is_safe_feature_name` before it reaches the completion item's `label`/`insert_text`/`text_edit`/`sort_text`, dropping the item outright on a malformed or spoofed name (resolves #1296)
- **deps-npm**: pnpm catalog hover now sanitizes the invisible-character class as strongly as the sibling diagnostic message, closing a gap where a non-bidi Unicode format character survived into hover but not the diagnostic (resolves #1266) (#1313)
- **deps-core**: `is_markdown_unsafe` (backing `escape_markdown`/`markdown_code_span`, used by hover, diagnostics, and completion) now also blocks soft hyphen, MONGOLIAN VOWEL SEPARATOR, invisible math operators, the deprecated format-control block, and the Egyptian Hieroglyph/Shorthand/Musical Symbol format-control blocks, closing a gap where these `sanitize_invisible`-stripped characters survived; the RTL/ZWNJ/ZWJ and Arabic/Syriac/Kaithi prefixed-format-sign exemptions from #1248 are unchanged (resolves #1323) (#1326)
- **deps-core, deps-gradle, deps-maven, deps-pypi, deps-swift, deps-gitlab-ci**: `BlockedRegistryOccurrence`, `BlockedSourceClass`, `RegistriesConfig`, `ScanTarget`, `GradleDependency`, `MavenDependency`, `ArtifactInfo`, `RequirementRef`, `SwiftDependency`, and `GitlabCiDependency` migrate their hand-written `Debug` impls to `#[derive(RedactingDebug)]`, closing the compile-time redaction gap for these types too (resolves #1325) (#1332)
- **deps-nuget**: harden `compile_requirement`/`format_version_replacing` against an unexpanded MSBuild property reference (`Version="$(SomeProperty)"`) being treated as a satisfiable requirement (see #1347) (#1352)
- **deps-maven, deps-gradle**: `format_version_replacing` no longer rewrites an unresolved `${property}`/`$var` placeholder to a literal version, including malformed-range shapes (resolves #1353) (#1363)
- **deps-composer**: `format_version_replacing`/`requirement_is_unresolved`/`compile_requirement` now no-op a native `self.version` root-package pin and an inline-alias constraint (`"dev-main as 1.0.0"`) instead of planning a destructive rewrite (resolves #1373) (#1375)
- **deps-core, deps-composer, deps-npm, deps-cargo, deps-dart, deps-pypi, deps-gitlab-ci**: new shared `lsp_helpers::requirement_contains_dollar_placeholder` predicate stops an externally-templated `$VAR`/`${VAR}` version placeholder from being rewritten in npm, Cargo, Dart, Poetry (`[tool.poetry.dependencies]`), and Composer manifests; `deps-gitlab-ci` now delegates its own `$VAR`/`${VAR}` detection to the shared predicate instead of a local duplicate (resolves #1374) (#1375)
- **deps-core**: new `RequirementResolution::requirement_is_placeholder` predicate centralizes the "never rewrite an unresolved placeholder" guard across all four edit paths (`plan_verified_fix`, `collect_update_candidates`, `build_unsatisfiable_fix_action`, the REFACTOR "Update to X" code action), replacing 6 independent per-ecosystem detectors with one trait override each across deps-maven, deps-gradle, deps-nuget, deps-bundler, deps-swift, deps-github-actions, deps-gitlab-ci, deps-npm, deps-cargo, deps-dart, deps-pypi, and deps-composer (resolves #1370) (#1376)
- **deps-core, deps-deno, deps-go**: `lsp_helpers::requirement_contains_template_placeholder` (renamed from `requirement_contains_dollar_placeholder`, since it now detects five template forms, not just `$`) recognizes `{{ VAR }}`/`{% ... %}`, `@VAR@`/`@project.version@` (dotted), `%VAR%`, and `<%= VAR %>` external-templating placeholders alongside `$VAR`/`${VAR}`, and deps-deno/deps-go gain `RequirementResolution`/`PackageRendering` overrides wired to it — closing the two ecosystems left unguarded by #1370/#1374/#1375 and the templating syntaxes left undetected by #1374 (resolves #1377, #1379) (#1383)
- **deps-composer, deps-gitlab-ci**: gain `reachable: true`/`formatter_guarded` conformance fixtures covering all five `requirement_contains_template_placeholder` forms — both crates already inherited the broadened detection via existing delegation, but had no fixture pinning it (resolves #1379) (#1383)
- **deps-gitlab-ci**: `contains_unresolved_gitlab_variable` now also recognizes GitLab CI/CD component input interpolation (`$[[ inputs.x ]]`) as an unresolved placeholder, closing a gap left unguarded by #1368/#1383 (resolves #1386) (#1388)
- **deps-maven**: `is_unresolved` now fully delegates to the shared `requirement_contains_template_placeholder`, closing a gap where the `@project.version@` resource-filtering placeholder was destructively rewritten (resolves #1384) (#1388)
- **deps-gradle, deps-nuget, deps-swift, deps-bundler, deps-github-actions**: `requirement_is_placeholder` now also composes the shared `requirement_contains_template_placeholder` detector (previously native-syntax-only), so `{{ VAR }}`/`@VAR@`/`%VAR%`/`${VAR}`/`<%= VAR %>` external-templating placeholders are no longer destructively rewritten to a literal version by `deps-cli update` or vulnerability-fix code actions in these five ecosystems (resolves #1390) (#1393)

### Fixed
- **deps-gradle**: completion inside a `build.gradle`/`build.gradle.kts` plugin version literal (`id("x") version "<cursor>"`) no longer misdetects a `Package` context and issues a stray Maven Central search on the typed version text, closing the gap #1436 left open for build scripts (resolves #1441) (#1446)
- **deps-core, deps-composer, deps-engine, deps-lsp, deps-cli**: hover, completion, and code actions now honor `composer.json`'s `minimum-stability` via a new `ParseResult::selection_context()`/`SelectionContext` type, instead of disagreeing with diagnostics about what "latest" means for the same dependency (resolves #1433) (#1443)
- **deps-lsp**: editing only `minimum-stability` (no dependency name/version change) now forces a full re-fetch under the new context, instead of leaving diagnostics/inlay hints on the stale stability until an unrelated edit refetches them (resolves #1433) (#1443)
- **deps-core**: version completion for a `v`-tagged registry (e.g. Composer's raw Packagist tags) now matches an unprefixed typed prefix instead of silently falling back to the unfiltered version list, and its `insert_text`/`text_edit` now preserve the typed prefix's style via a new `PackageRendering::format_version_for_completion` hook instead of splicing the registry's raw candidate text verbatim (resolves #1435) (#1443)
- **deps-composer**: update code actions now preserve an unprefixed requirement's style instead of forcing a `v`-prefix from Packagist's raw tag text (resolves #1435) (#1443)
- **deps-core, deps-npm, deps-pypi, deps-go**: a registry-config entry rejected for a reason other than a blocked host (malformed URL, non-https, embedded userinfo, undefined `${VAR}`, disallowed `${VAR}` expansion) now surfaces a warning diagnostic instead of silently dropping the dependency with no user-visible feedback; NuGet tracked separately in #1442 (resolves #1438) (#1445)
- **deps-core, deps-go**: Go hover now renders `Fixed in: v0.55.0` instead of `Fixed in: 0.55.0`, converting an OSV advisory's `fixed_versions` through `OsvNaming::osv_version_to_native` before display, matching the hover's `Current`/`Recent versions` lines (resolves #1423)
- **deps-core, deps-cargo, deps-npm, deps-pypi, deps-go, deps-nuget, deps-gitlab-ci, deps-swift, deps-github-actions**: shared registry/log helpers (`register_capped`, `validate_index_url`, `InvalidEntry::logged`, pagination warnings) now take a typed `EcosystemId` instead of an ad-hoc `&'static str`, so the `ecosystem` tracing field is always spelled the same way for a given ecosystem (previously `cargo`/`Cargo`, `nuget`/`NuGet`, `gitlab-ci`/`GitLab CI` disagreed across call sites, splitting `RUST_LOG`/log-query results) (resolves #1425)
- **deps-lsp**: the tier-3 license pre-fetch (Dart/Swift/Gradle/Deno) now re-runs alongside the OSV rescan on a lock-file-only resolved-version change, in both the lock-file-watcher and debounced-edit paths, instead of leaving `DocumentState::licenses` stale until the next manifest edit or document reopen (resolves #1407) (#1415)
- **deps-core**: hover's "Press `Cmd+.` to update version" footer is no longer shown for a dependency whose requirement is an unexpanded template placeholder, since `codeAction` returns zero actions for it under the write-path guard from #1393 (resolves #1402) (#1408)
- **deps-go**: `parse_require_line` no longer truncates a `require` line's version to its first whitespace-delimited token when there is more than one token on the version side of the line, fixing manifest corruption from a partial edit range on a multi-token external-templating placeholder — including one embedded inside an otherwise version-shaped leading token (e.g. `v0.{{ .Minor }}.0`, not just a placeholder starting the field like `{{ .NetVersion }}`) (resolves #1379) (#1383)
- **deps-bundler**: multi-constraint `gem` requirements now capture and rewrite every positional constraint instead of only the first, fixing contradictory version-fix rewrites and restoring code actions/completion for such dependencies (resolves #1366) (#1369)
- **deps-nuget**: `NuGetLockParser::locate_lockfile` now checks `packages.<Project>.lock.json` before the plain `packages.lock.json` and normalizes spaces in the project name to `_`, matching NuGet's own lookup order (resolves #1364) (#1369)
- **deps-nuget**: a project with no `packages.lock.json`/`packages.<Project>.lock.json` of its own no longer falls back to an unrelated ancestor project's lock file, since NuGet lock files are per-project, not workspace-shared (resolves #1357) (#1362)
- **deps-nuget**: `%(MetadataName)` item-metadata and `@(ItemList)` item-list MSBuild reference syntax are now recognized as unresolved everywhere `$(PropertyName)` already was — parse-time version degrade guards, `requirement_is_unresolved`, and `validate_package_name` — closing gaps where they still offered version-rewrite code actions, completions, and diagnostics, or rendered an incorrect "Invalid package name" diagnostic for an unresolved `Include` reference (resolves #1355) (#1362)
- **deps-nuget**: an ancestor directory's `packages.lock.json` no longer shadows a nested project's own `packages.<Project>.lock.json` one directory closer (resolves #1351) (#1356)
- **deps-core, deps-engine, deps-cli**: `plan_vulnerability_fix` now returns a typed reason instead of collapsing every failure into `None` (resolves #1350) (#1361)
- **deps-cli**: `Outcome::Applied` now carries its edit directly, preventing a state where success is reported without writing (resolves #1349) (#1361)
- **deps-core, deps-lsp**: the vulnerability-fix code action no longer offers a manifest rewrite when the declared requirement already resolves forward to the recommended fix version under the ecosystem's own resolution rules, matching `deps-cli update --security-only`'s existing `RequiresLockfileUpdate` classification (resolves #1344) (#1346)
- **deps-nuget**: a bare/minimum-floor `Version="1.0.0"` requirement no longer suppresses its own vulnerability-fix rewrite — NuGet resolves such a floor to its lowest satisfying version, not forward to the fix, unlike an auto-following range (resolves #1344) (#1346)
- **deps-cli**: `update --security-only` now reports a requirement-admitting-fix-but-yanked dependency as `Unfixable(Yanked)` instead of `RequiresLockfileUpdate`, since a yanked fix target is never actually selected by re-resolving regardless of what the requirement admits (resolves #1344) (#1346)
- **deps-core**: `#[redact(key)]` fields generated by `RedactingDebug` no longer force a `String` allocation on every `Debug` format call, restoring the `Cow`-based no-alloc path for the common no-redaction-needed case (resolves #1333) (#1341)
- **deps-lsp**: `test_guarded_reparse_skip_does_not_abort_pre_existing_background_task` no longer flakes under CI-runner scheduling load, replacing a fixed 200ms sleep with a poll loop (resolves #1337) (#1340)
- **deps-core, deps-maven, deps-swift**: package-name completion items now preserve the registry's own relevance ranking in `sort_text` (tiering an exact-prefix match ahead of a same-rank fuzzy match) instead of forcing alphabetical client-side sorting (resolves #1282) (#1293)
- **deps-lsp**: raw-text fallback package completion now matches the primary path's `sort_text`/`filter_text`/`detail`/`documentation`/`insert_text_format`, and gains the same latest-version safety gate (resolves #1284) (#1291)
- **deps-swift, deps-cli, deps-lsp**: GitHub-backed live tests now skip instead of panicking when rate-limited with no `GITHUB_TOKEN` configured (#1297)
- **deps-npm**: live-search test no longer asserts that npm's tokenized search returns a specific package for a partial-prefix query (#1297)
- **tests**: every bare `#[ignore]` annotation across the workspace now carries a reason string (#1297)
- **deps-lsp**: raw-text fallback package completion now also threads the registry result's index/typed prefix into `sort_text`, closing the same relevance-ranking gap as #1282 on this second, independently-built completion path (resolves #1294) (#1293)
- **deps-cli**: `CheckFinding.requirement` is now sanitized and length-capped before reaching JSON output, closing an ANSI-escape/bidi-override leak (resolves #1258) (#1301)
- **deps-maven**: `maven-metadata.xml` parse errors are now redacted before reaching `DepsError::CacheError`, closing a credential leak from a malformed tag name (resolves #1249) (#1301)
- **deps-cli**: `CheckFinding.manifest_path` is now sanitized before reaching table (default) and JSON output, and every other path-carrying warning/error message deps-cli prints is sanitized at a single construction-time chokepoint instead of per call site, closing the same Trojan-Source-class ANSI-escape/bidi-override leak class as #1301 (resolves #1299) (#1304)
- **deps-cli, deps-core**: `CheckFinding.requirement` sanitization now also redacts credential-shaped text via a new `deps_core::lsp_helpers::redact_requirement_for_diagnostic` helper, replacing deps-cli's locally duplicated length-cap constant (resolves #1300) (#1304)
- **deps-core, deps-lsp**: raw-text fallback completion now rewrites `filter_text` to the raw typed prefix for registries that normalize search queries, fixing PyPI PEP 503 dotted-name completions dropped by some LSP clients (resolves #1289) (#1306)
- **deps-cargo**: feature-flag completion is now capped at 5 items with deterministic alphabetical truncation and an accurate `is_incomplete` flag, instead of an unbounded, arbitrarily-ordered list (resolves #1302) (#1307)
- **deps-core**: an unauthenticated GitHub 403/429 is now classified as a genuine rate limit only when the response confirms exhaustion (`X-RateLimit-Remaining: 0` or a `Retry-After` header), so `unwrap_or_skip_github_rate_limit` no longer silently skips an unrelated 403 cause as expected (resolves #1295) (#1308)
- **deps-core**: `DepsError::fetch_failure` and its telemetry-label sibling classifier are now exhaustive matches with no wildcard arm, so a future variant cannot silently lose its diagnostic hint (resolves #1244) (#1308)
- **deps-cargo**: `Cargo.lock` `sparse+` sources now classify as `ResolvedSource::Registry` instead of falling through to the `::Path` catch-all (latent — no current consumer branches on the variant yet) (resolves #1320) (#1324)
- **deps-nuget**: added a regression test proving `own_auth_id` actually separates `HttpCache` entries between distinct credentials against the same feed URL, closing a coverage gap where the invariant was untested (resolves #1026) (#1331)
- **deps-gitlab-ci**: a Tag-shaped ref with an embedded, non-leading variable reference (e.g. `v16.0-$BUILD`) no longer reports permanently `Outdated`; it's now correctly classified `Unresolved` (part of #1370) (#1376)
- **deps-core**: hover and diagnostics now surface a "vulnerability data not checked" signal when the OSV scan skipped a dependency for a non-offline reason (most commonly no resolved/exact version to query), instead of rendering nothing and looking identical to a scanned, clean dependency (resolves #1392) (#1394)
- **deps-lsp**: `handle_lockfile_change` now re-runs the OSV vulnerability scan for a document whose resolved version newly appeared or changed, instead of leaving `Skipped`/`Clean`/`Vulnerable` results stale after a lock-file-only change (resolves #1395) (#1397)
- **deps-cli**: an auto-discovered `deps.toml` with excessive array/table nesting now returns a `ConfigError` instead of overflowing the stack (resolves #1403) (#1405)
- **deps-lsp**: a debounced manifest edit that changes no dependency itself now still re-runs the OSV vulnerability scan when the lock file moved a resolved version underneath it, matching `handle_lockfile_change`'s existing check (resolves #1399) (#1410)
- **deps-lsp**: for a tier-3, dedicated-fetch ecosystem (Dart/Swift/Gradle/Deno), a dependency whose resolved (in-use) version moves now has its cached license evicted synchronously, instead of `DocumentState::merge_licenses` keeping the previous version's license visible if the triggered re-fetch fails that round (resolves #1424) (#1427)
- **deps-lsp**: `handle_lockfile_change` no longer wipes `resolved_versions`/`resolved_version_candidates` to empty maps when the lock-file reload itself fails; previously-resolved data now survives a transient reload error instead of being discarded until the next successful reload (resolves #1424) (#1427)
- **deps-gradle**: completion inside a `settings.gradle`/`settings.gradle.kts` plugin version literal (`id("x") version "<cursor>"`) no longer misdetects a `Package` context and issues a stray Maven Central search on the typed version text; it now correctly offers no completion. Scoped to that specific position, not every completion in a Settings-kind file — a compact `group:artifact:version` coordinate elsewhere in the same file still reaches the same detection `build.gradle(.kts)` uses (verified live, part of #1436). The identical bug pattern in `build.gradle(.kts)`'s own `plugins { }` block is out of scope here; tracked separately (#1441) (#1445)

### Breaking
- **deps-core, deps-engine**: `Registry::get_latest_matching_with_context`/`get_latest_matching_from`/`select_latest_matching_with_context`, and `deps_engine::classify::fetch::fetch_latest_versions_parallel`, now take `&SelectionContext` instead of `Option<&str>`, so a caller with a `ParseResult` in scope threads the typed value straight through instead of extracting it to a string early (resolves #1433)
- **deps-core**: `osv::VulnerabilityMap`/`ScanTarget::key`/`OsvClient::check_candidates` are now keyed/typed by `VulnKey` instead of `String`; `VulnKey::into_string` is removed (resolves #1413) (#1418)
- **deps-lsp**: `DocumentState::update_resolved_versions` is no longer public (resolves #1398) (#1410)
- **deps-engine**: `classify::resolved::load_resolved_versions` now returns a 3-tuple, adding a `bool` distinguishing a successful reload (including a genuinely absent/empty lock file) from a parse failure, so callers that treat an empty-to-non-empty transition as a staleness signal can avoid mistaking one for the other (resolves #1407) (#1415)
- **deps-engine**: `classify::resolved::load_resolved_versions` now returns the new exhaustive `LockfileLoad` enum (`Absent`/`Loaded`/`Failed`) instead of the `(HashMap, HashMap, bool)` 3-tuple from #1415; new `classify::resolved::parse_known_lockfile` helper shared with `deps-lsp`'s `handle_lockfile_change` (resolves #1424) (#1427)
- **deps-core**: `edit::plan_vulnerability_fix` returns `Result<PlannedUpdate, VulnFixSkip>` instead of `Option<PlannedUpdate>`; `edit::fix_target_is_verified` is `pub(crate)` again (part of #1350) (#1361)
- **deps-cli**: `update::Outcome::Applied` is now a tuple variant carrying `ManifestEdit`; `update::PlannedUpdateItem` no longer has a separate `edit` field (part of #1349) (#1361)
- **deps-core**: `Ecosystem::generate_hover` and `lsp_helpers::generate_hover` now return the protocol-agnostic `deps_core::hover::Hover` instead of `tower_lsp_server::ls_types::Hover` (resolves #1277) (#1309)
- **deps-cli**: `WalkOutcome`'s `manifests`/`walk_errors`/`unrecognized_explicit_paths`/`ignored_manifests`/`broken_manifest_symlinks` fields are private now, read via new `manifests()`/`walk_errors()`/`unrecognized_explicit_paths()`/`ignored_manifests()`/`broken_manifest_symlinks()` accessors (resolves #1305) (#1312)
- **deps-core**: `osv::Advisory::url` is private now, read via a new `url()` getter; `Advisory::new` returns `Option<Self>` and no longer takes a `url` parameter (resolves #1271) (#1298)
- **deps-core**: `completion::build_package_completion` gains `index: usize` and `prefix: &str` parameters, used to preserve registry relevance ranking in `sort_text` (resolves #1282) (#1293)
- **deps-core**: `completion::build_feature_completion` now returns `Option<CompletionItem>` instead of `CompletionItem`, dropping the item when `feature_name` fails `is_safe_feature_name` (resolves #1296)
- **deps-core**: `DepsError::RateLimited` gains `verified: bool` and `source_status: Option<u16>` fields (now `#[non_exhaustive]` itself, so future field additions won't repeat this); a downstream crate matching or constructing it without `..` needs updating (part of #1295) (#1308)
- **deps-core**: `quote_scan::ScanSyntax` is now `#[non_exhaustive]`, so a future scanner dialect variant (like `Groovy`, added in #1186) won't repeat that break silently (resolves #1226) (#1321)
- **deps-core**: `registry::CapResult` is now `#[non_exhaustive]` (part of #1226) (#1321)
- **deps-core**: `DepsError::ParseError` is now `#[non_exhaustive]`; a downstream crate matching or constructing it without `..` needs updating — use the new `DepsError::parse_error(file_type, source)` constructor instead of a struct literal (resolves #1250)
- **deps-core**: `lsp_helpers::dedup_overlapping_edits` moved to `edit::dedup_overlapping_edits` and is now generic over a new `edit::EditSpan` trait instead of taking/returning `Vec<tower_lsp_server::ls_types::TextEdit>` only; re-exported at `lsp_helpers::dedup_overlapping_edits` unchanged for existing `Vec<TextEdit>` call sites (part of #1329) (#1343)
- **deps-lsp**: removed the dead `deps-lsp.updateVersion` `executeCommand`, its `UpdateVersionArgs` argument type, and its registration in `executeCommandProvider` — it bypassed `EcosystemFormatter` and the central placeholder gate, always TOML/JSON-quoting the replacement text regardless of manifest type, and had no in-tree producer; the REFACTOR "Update to X" code action already covers its use case with the shared safeguards. A client still invoking `deps-lsp.updateVersion` by name now gets a silent `Ok(None)` no-op instead of an error, matching every other unrecognized `workspace/executeCommand` request `execute_command` receives (resolves #1378) (#1381)
- **deps-core**: `RequirementResolution::requirement_is_placeholder`'s default implementation now delegates to the shared `requirement_contains_template_placeholder` detector instead of returning `false`; every ecosystem's own override now composes it via `shared || native` or was deleted where it became redundant. The write-path guard is centralized in new `edit::requirement_is_placeholder_for`/`edit::replacement_text` helpers, and the 14 per-crate hand-rolled guards inside `format_version_replacing`/`_for` are removed — a direct call to `format_version_replacing_for` no longer re-checks for a placeholder itself. A downstream `Ecosystem`/`RequirementResolution` implementor relying on the old `false` default now correctly skips a templated placeholder in the write path too (resolves #1391, closes #1390) (#1393)
- **deps-core**: `EcosystemRegistry::get`/`ecosystem_ids` and `deps-lsp`'s `ReparseScope::Ecosystems`/`ServerState::workspace_registry_ecosystems` are now keyed by `EcosystemId` instead of `&str`, closing the routing-typo bug class fixed once already for #118; `DocumentState::ecosystem_id()` is removed, read the typed `ecosystem` field directly (part of #1400) (#1416)
- **deps-core**: new `osv::VulnKey`/`VulnKeys` newtypes and a now-`pub` `osv::vuln_key_for`/`lsp_helpers::resolve_scan_outcome` (previously `pub(crate)`) centralize the vulnerability-map key/fallback lookup that was independently hand-written in four places; `VulnerabilityMap` itself stays `HashMap<String, ScanOutcome>` for now (follow-up: #1413) (part of #1400) (#1416)
- **deps-core**: `osv::vulnerability_keys` now returns the new `VulnKeys` type instead of `HashMap<Range, String>`; there is no public lookup by `Range` on it, only `osv::vuln_key_for`/`lsp_helpers::resolve_scan_outcome` (part of #1400) (#1416)
- **deps-engine**: `setup::register_ecosystems` now returns `Vec<EcosystemId>` instead of `Vec<&'static str>` (part of #1400) (#1416)

### Changed
- **deps-lsp**: `handle_lockfile_change`'s lock-file-driven OSV rescan is now supervised, logging a panic instead of silently dropping it (resolves #1399) (#1410)
- **deps-lsp**: diagnostics snapshotting/generation across the open, change, lockfile-change, and pull-diagnostics paths now share one `DiagnosticsSnapshot` type (resolves #1399) (#1410)
- **deps-core**: package-completion builders no longer allocate and immediately discard `insert_text`/`text_edit` when the caller doesn't need them (resolves #1290) (#1306)
- **deps-core, deps-gitlab-ci**: `impl_parse_result!` collapses its 8 near-identical match arms into one, using `$(...)?` optional-fragment matching; `deps-gitlab-ci`'s hand-written `ParseResult` impl now uses the macro (resolves #985) (#1339)
- **deps-core, deps-github-actions, deps-gitlab-ci, deps-npm**: six of the nine `= 128` diagnostic-value length-cap constants now share one `deps_core::lsp_helpers::MAX_DIAGNOSTIC_VALUE_CHARS`, removing a duplicate `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS` independently declared in two crates (resolves #1278) (#1313)
- **deps-core, deps-cargo, deps-npm, deps-dart, deps-pypi, deps-maven, deps-gradle, deps-nuget, deps-composer, deps-swift, deps-bundler**: `RequirementResolution::requirement_is_unresolved`'s default now delegates to `requirement_is_placeholder`, removing 10 byte-identical per-ecosystem overrides; `deps-github-actions`/`deps-gitlab-ci` keep their own override since their two predicates genuinely differ (part of #1380) (#1381)
- **ci**: bump `taiki-e/install-action` to v2.87.18 and `jsonschema` to 0.57 (#1315)
- **deps-core, deps-github-actions, deps-gitlab-ci, deps-dart, deps-npm**: new `deps_core::check_yaml_bounds` helper centralizes duplicated YAML nesting-depth/expansion-guard wiring across 5 call sites (resolves #1245) (#1314)
- **deps-core**: URL/declaration-key/parse-error redaction and the in-memory secret wrapper moved from `net_policy`/`secret` into a new `redact` module; old paths are kept as re-exports, so no call site needs updating (resolves #1247, #1216) (#1316)
- **deps-core**: `redact` module dedupes the double URL-parse on the declaration-key redaction hot path and avoids a second allocation on its opaque-key no-op path (resolves #1317) (#1327)
- **deps-core, ci**: `redacting_debug_compile_fail` trybuild test is now `#[ignore]`d (slow cold-cache sandbox rebuild); still run explicitly via dedicated steps in `ci.yml`'s `test`, `cross-check` (i686), and `coverage` jobs, and excluded from `live-registry-tests.yml`'s network-gated sweep (#1345)
- **ci**: bump `taiki-e/install-action` to v2.87.19; refresh `Cargo.lock` (`thiserror` 2.0.21) (#1389)
- **ci**: bump `taiki-e/install-action` to v2.87.20 and `github/codeql-action` to v4.38.2 (#1396)
- **deps-core, deps-engine, deps-lsp, deps-cli**: new `deps_core::test_util::StubFormatter` (const-constructible `EcosystemFormatter` test double) replaces 29 hand-rolled mock formatter structs inside `#[cfg(test)]` modules across the workspace; public-API `///` doctest examples (illustrating manual trait implementation) are unchanged; no production behavior change (resolves #1401) (#1411)
- **deps-core, deps-cargo, deps-pypi, deps-gradle, deps-cli**: new `deps_core::parse_toml_checked` (`CheckedTomlError`) replaces per-crate TOML depth-guard-then-parse boilerplate at all 10 call sites (resolves #1406) (#1412)
- **deps-core, deps-cli, deps-gitlab-ci, deps-github-actions, deps-swift**: `HttpCache::set_offline`/`set_cache_enabled` now take `NetworkMode`/`CacheMode`, `DepsError::rate_limited`'s `verified` field is now `RateLimitEvidence`, and `deps-cli`'s `dry_run`/`offline`/`had_execution_error` boolean parameters are now typed (`format::DryRun`, `deps_core::NetworkMode`, `exit::ExecutionOutcome`), replacing boolean-blind public APIs (part of #1436) (#1445)
- **deps-gradle, deps-nuget, deps-npm**: manifest/lockfile kind is now derived from a private typed `from_uri`/`from_path` classification (mirroring `deps-pypi`'s existing pattern) instead of independently re-matching the URI/filename string at each call site (part of #1436) (#1445)

### Documentation
- mdBook overhaul: added basics sections to every ecosystem page, new `deps-engine` and GitHub Action pages, and a restructured table of contents separating everyday usage from architecture/internals (#1288)

## [1.2.0] - 2026-09-21

### Added
- **deps-core**: new `net_policy::redact_parse_error_for_log`/`parse_error_source` helpers, redacting a `toml_span`/`yaml-rust2` parse error before it reaches a log sink (resolves #1240) (#1241)
- **deps-core**: new `rate_limit` module with a `RateLimitGate` mechanism shared by deps-github-actions and deps-gitlab-ci (#1218)
- **fuzz**: `redact_declaration_key` fuzz target, covering the client-visible declaration-key redaction gate for blocked-registry diagnostics (resolves #1207) (#1213)
- **deps-maven**: version completion now offers items inside a self-closing `<version/>` tag, replacing the whole tag with `<version>X</version>` via an explicit text edit instead of relying on a cursor-position insert (resolves #1167) (#1189)
- **deps-composer**: `PackagistRegistry` gained a mockable test constructor and an end-to-end completion test proving the real `VERSION_OPERATOR_CHARS` operator-stripping fix from #1137, not just a `deps-core`-side copy of it (resolves #1171) (#1193)
- **ci**: release workflow publishes a CycloneDX SBOM (JSON) for `deps-lsp` and `deps-cli` alongside each release's binaries (resolves #1154) (#1169)
- **ci**: weekly + push-to-main OpenSSF Scorecard workflow, uploading results to the Security tab (#1158)
- **ci**: CodeQL SAST scanning for Rust source and GitHub Actions workflow files, on push/PR/weekly schedule (resolves #1152) (#1163)
- **ci**: release archives signed with Sigstore/cosign keyless signing alongside existing SHA256 checksums (resolves #1153) (#1163)

### Breaking
- **deps-core**: `Diagnostic::message`/`code`/`RelatedInformation::message` are now private, accessed via `message()`/`code()` getters, with `with_code` now sanitizing like `message` does; `Diagnostic` no longer implements `Default` — closes a sanitization-backstop bypass via `Default::default()` or a direct field write (resolves #1280) (#1281)
- **deps-cli**: `config::ConfigError::Toml`/`Deserialize` now store a redacted message instead of the raw parse error, closing a credential leak to stderr/logs (resolves #1240) (#1241)
- **deps-cli**: `walk::walk` takes `GitignorePolicy`/`SymlinkPolicy` enums instead of two adjacent, transposable `bool` parameters; `CheckArgs` gained matching `gitignore_policy()`/`symlink_policy()` accessors (resolves #1224) (#1230)
- **deps-core**: `registry::register_capped`/`register_capped_with_occupied` return `CapResult` instead of `bool` (#1218)
- **deps-gitlab-ci**: removed `pub const MAX_GITLAB_ROUTES`; the cap is now `deps_core::registry::MAX_ALTERNATE_REGISTRIES` (#1218)
- **deps-core**: `lsp_helpers::git_ref::locate_value_span` gains a 4th `is_quoted: bool` parameter; new `MarkedScalar::is_quoted()` replaces the marker-byte-based quote inference the empty-value correction previously relied on (#1194)
- **deps-core**: removed `completion::complete_versions_generic`; `completion::complete_versions_generic_from` now requires an additional `formatter: &dyn lsp_helpers::SourcePolicy` parameter (resolves #1136)
- **deps-core**: `PackageName` no longer implements `Display`/`ToString`; its `Debug` impl now redacts a credential-shaped name instead of deriving, so `?name` and any struct embedding a `PackageName` are safe by construction (resolves #1217) (#1219)
- **deps-core, deps-cargo, deps-npm, deps-bundler, deps-deno, deps-maven, deps-nuget, deps-dart, deps-composer**: `Registry::search` is renamed to `search_raw`, with a new inherent `search` gate on `dyn Registry` (which an implementor cannot override) that rejects a credential- or query-bearing search string before it ever reaches a registry, and redacts the 9 concrete registries' own `search` tracing spans (resolves #1215) (#1219)

### Changed
- **ci**: bumps `taiki-e/install-action` to v2.87.17 across CI and release workflows (flagged as outdated by code scanning) (#1269)
- **deps-pypi**: `truncate_for_log` now delegates to `deps_core::net_policy::redact_parse_error_for_log` instead of duplicating its redact-then-truncate algorithm (#1240) (#1241)
- **deps-core, deps-npm, deps-pypi, deps-go, deps-composer, deps-swift, deps-nuget, deps-cargo, deps-dart, deps-bundler, deps-deno**: `Ecosystem::complete_version` now has a shared default implementation (backed by a new `version_operator_chars` hook), replacing ten byte-identical hand-written implementations (resolves #1223) (#1235)
- **deps-gitlab-ci**: `register_alternate` now logs one cap-reached warning per refused route key instead of one per batch (#1218)
- **deps-core, deps-gradle**: Gradle's quote/comment scanning migrated onto a shared `deps-core::quote_scan::ScanSyntax::Groovy` scanner instead of a crate-local implementation (resolves #1174) (#1186)
- **deps-github-actions, deps-gitlab-ci**: static SHA-pin quickfix/hover-splice logic deduplicated into a shared `ShaPinning` trait in `deps-core::lsp_helpers::git_ref`; GitLab's live-fetch dynamic-component pin and GHA's tag-index footer remain ecosystem-local (resolves #1138) (#1177)
- **deps-cli**: added a regression test pinning `walk_directory`'s `DotDirs::Descend` call-site wiring at hidden-ecosystem sub-roots (resolves #1165) (#1177)
- **ci**: `crates/github-action`'s Alpine base image pinned by digest, tracked by Dependabot for security-patch bumps (resolves #1155) (#1169)
- **deps-cli**: `walk_directory`'s positional bool triple replaced with a `WalkOptions` struct and `DotDirs` enum, closing a swap-silent transposition risk on the gitignore/symlink containment gate (resolves #1135) (#1164)
- **ci**: `release.yml`'s top-level GITHUB_TOKEN permissions scoped to a read-only default, with `contents: write` granted per-job only where needed (resolves #1151) (#1163)
- **deps-gradle, deps-maven**: version-completion dependency lookup deduplicated into a shared `deps-core` helper (resolves #1134) (#1145)
- **ci**: `deps-lsp-check` and `docker-build-and-scan` now block `ci-success` (#1130, #1140)

### Fixed
- **deps-core**: `Diagnostic::new`/`RelatedInformation::new` now sanitize `message` as a defense-in-depth backstop on the constructor path, on top of existing producer-side sanitization (resolves #1276) (#1279)
- **deps-core**: sanitizes and caps the registry- and lockfile-derived version strings interpolated into every inlay-hint version label, closing a sink missed by the prior sanitization sweep (resolves #1268) (#1270)
- **deps-core**: hover header's dependency name (rendered label) is now capped at 128 characters, and its link destination strips bidi/invisible characters as defense-in-depth on top of the existing producer-side `package_url` conformance gate (resolves #1259) (#1270)
- **deps-gitlab-ci**: a credential-shaped `include:` host value no longer leaks unredacted into the unresolved-host diagnostic message (resolves #1254) (#1264)
- **deps-npm**: sanitizes invisible/bidi-override characters in the raw `catalog:...` specifier and the dependency/catalog name interpolated into the catalog diagnostic message (resolves #1256) (#1264)
- **deps-core**: sanitizes and caps unbounded, unsanitized registry- and manifest-derived version strings (unsatisfiable-requirement, yanked, outdated, pre-release-enrichment, deprecation reason/replacement) and OSV advisory summary text interpolated into LSP diagnostic messages, via a new `sanitize_advisory_text_for_diagnostic` helper for free-text prose (resolves #1263, #1262) (#1267)
- **deps-core**: sanitizes invisible/bidi-override characters in the license-policy-violation diagnostic's interpolated license text (resolves #1257) (#1261)
- **deps-core**: sanitizes invisible/bidi-override characters in the blocked-registry diagnostic's interpolated raw value and declaration key (resolves #1255) (#1261)
- **deps-core, deps-github-actions, deps-gitlab-ci**: sanitizes invisible/bidi-override characters in mutable-ref-pin diagnostic messages, the unresolved-host diagnostic, and both "Pin to commit SHA" code-action titles (the shared static-tag-index path and GitLab's dynamic-component path), and widens the shared `escape_markdown`/`markdown_code_span` hover helpers with the same character class, closing a Trojan Source (CVE-2021-42574) spoofing/report-forging vector; the two code-action titles are now also capped at 128 characters, where an oversized name previously rendered unbounded (resolves #1252, #1248) (#1260)
- **deps-core, deps-cli**: a credential-shaped or control-character/bidi-override dependency name no longer leaks unredacted into the unknown-package/license-policy/blocked-registry diagnostic messages, the CLI JSON `dependency_name` field, or the SARIF fingerprint, via a new shared `redact_name_for_diagnostic` helper (resolves #1242, #1246) (#1253)
- **deps-maven, deps-nuget**: a malformed XML tag whose name is credential-shaped no longer leaks the credential into `quick_xml` parse-error log/stderr output (resolves #1243) (#1251)
- **deps-cargo, deps-dart, deps-gradle, deps-npm, deps-cli**: a duplicate TOML table/YAML mapping key whose name is credential-shaped no longer leaks the credential into parse-error log/stderr output across Cargo.lock, Cargo.toml, pubspec.lock, gradle/libs.versions.toml, pnpm-lock.yaml, and deps.toml (resolves #1240) (#1241)
- **deps-pypi**: `truncate_for_log` now redacts credentials before truncating and gates value-redaction to avoid mangling benign colon-shaped text, closing a leak of PEP 508 direct-reference URL and lock-file credentials to logs (resolves #1228) (#1239)
- **deps-core, deps-deno, deps-npm, deps-lsp**: an `.npmrc` change now reparses every ecosystem that watches it (not just one) and forces a full refetch instead of a silent no-op diff, so an open `deno.json`/`package.json` document picks up the new registry routing (resolves #1232) (#1234)
- **deps-deno**: `npm:`-scope imports classified `AlternateRegistry` via `.npmrc` are now actually fetched through the resolved registry instead of being silently dropped from the fetch queue, matching `package.json`'s behavior for the identical entry (resolves #1227) (#1231)
- **deps-npm**: a malformed `.npmrc` line (missing `=`) no longer logs its raw content, closing a credential leak when the line is a typo'd auth-shaped entry; the warning now names only the file path and line number (resolves #1229) (#1233)
- **deps-composer**: a bare (no `only` filter) repository entry now cross-checks `composer.lock`'s `source.type` to classify a matching dependency as `Path` (never `Git`) instead of `Registry` (resolves #1212) (#1221)
- **deps-gradle**: a repository with an explicit `url` and a `content { }` restriction (`includeGroup`/`includeGroupByRegex`/`includeModule`) now classifies its matching dependency as a custom registry source instead of `Registry` (resolves #1212) (#1221)
- **deps-deno**: `npm:`-scope `.npmrc` classification now shares `NpmEcosystem`'s live policy and cached config instead of re-reading `.npmrc` with a hardcoded policy on every parse (resolves #1212) (#1221)
- **deps-maven, deps-gradle**: `MavenDependency`, `ArtifactInfo`, and `GradleDependency` now redact `group_id`/`artifact_id` in their `Debug` output, closing the same credential-shaped-coordinate leak class as #1217/#1219 for a raw field sitting next to a redacted `name` (resolves #1220) (#1225)
- **deps-swift, deps-gitlab-ci, deps-core, deps-bundler, deps-pypi, deps-npm**: closes the remaining CWE-532 Debug-leak sites with manual, redacting `Debug` impls, backed by a new shared conformance macro (resolves #1222) (#1236)
- **deps-core, deps-npm, deps-composer, deps-go, deps-maven, deps-deno**: closes the `can_resolve_source` privacy gate's structural inertness for npm (git/tarball/local-path/workspace specifiers), Composer (`repositories` package/artifact/wildcard-filtered entries, `packagist.org: false`), Go (`replace`-to-local-path propagated to its `require` entry), Maven (`scope: system`/`systemPath`), and Deno (npm-scope via `.npmrc`), preventing a private/local dependency's name from being sent to a public registry; adds a mandatory per-ecosystem conformance check so a future ecosystem cannot silently skip it (#1202) (#1211)
- **deps-core**: unifies `SourcePolicy::can_resolve_source`/`PackageRendering::suppress_package_url` behind a single `resolves_alternate_registry()` hook and fixes their default polarity, so an ecosystem that never overrides them now safely suppresses a misleading public-registry hover link for a non-registry dependency instead of showing one by default (resolves #1203) (#1211)
- **deps-lsp**: a panic in the `didChangeConfiguration` reparse worker is now logged instead of silently leaving open documents un-reparsed (#1218)
- **deps-core, deps-engine, and all 14 ecosystem crates**: package/module names are now redacted before reaching logs, error messages, or LSP client-visible diagnostics, closing a workspace-wide credential-shaped-name leak in the fetch/classify path and its error types (resolves #1209) (#1214)
- **deps-core**: hover and code-action registry version fetches now respect a 10s deadline instead of blocking indefinitely, preventing a slow or sequential-fallback registry lookup from stalling an interactive LSP request (resolves #1204) (#1210)
- **deps-core, deps-swift, deps-maven, deps-lsp**: completion no longer forwards a credential-bearing search prefix to the registry or logs it unredacted (resolves #1206) (#1208)
- **deps-core**: blocked-registry diagnostic's `declaration_key` redaction now gates on credential shape rather than a URL-separator substring, closing a credential-leak gap for opaque-label-prefixed keys regardless of separator, e.g. `"source:feed/user:pass@host"` or `"named:user:pass@host"` (resolves #993) (#1201)
- **deps-gradle**: version-completion same-line fallback no longer misattributes a non-dependency or still-unparsed literal on a shared manifest line to a nearby real dependency (resolves #1191) (#1196)
- **deps-core**: `detect_completion_context`'s hand-inlined strict-containment check (package-name completion) now reuses `lsp_helpers::position_in_range` instead of re-deriving it (resolves #1147) (#1196)
- **deps-lsp**: `ServerState::documents` and every request/response URI are now keyed by one canonical `Uri` form, so requests spelling the same open document differently (e.g. `file://localhost/x` vs `FILE:///x`) resolve to the same document instead of a stale/absent second entry; removes the three per-handler URI-rekey fixups from #1071 (resolves #1086) (#1198)
- **deps-maven**: `<version>` ancestry resolution now uses `quick_xml`'s event-based parser instead of a hand-rolled scanner, fixing ancestry misattribution when a quoted attribute value contains an unescaped `>` (resolves #1192) (#1197)
- **deps-maven**: version completion no longer misattributes a `<version>` or self-closing `<version/>` tag to a nearby `<dependency>`/`<plugin>` on a minified pom.xml unless it is structurally nested inside one (resolves #1181) (#1190)
- **deps-core, deps-lsp, deps-github-actions, deps-maven**: completion's fallback-to-package-name-search gate now runs on a `CompletionOrigin` stamped by whichever dispatch resolved the cursor context, instead of an opt-in `suppress_fallback` flag only GitHub Actions set — closes the fallback leak for GitHub Actions SHA-pin comments, PyPI/Go bare `Version` positions lacking a `=`, and Maven's self-closing `<version/>` tag (resolves #1195) (#1200)
- **deps-github-actions**: hover's "Press Cmd+. to update version" footer now uses the same centralized SHA-pin eligibility check as the quickfix/code-lens, no longer advertising the action for a flow-style step where the quickfix is withheld (resolves #1178) (#1187)
- **deps-github-actions**: mutable-tag-ref diagnostic's message branch now uses the same structural eligibility check as the SHA-pin quickfix, instead of claiming an automated fix is available for a quoted-scalar or flow-style tag pin where it is actually withheld (resolves #1188) (#1194)
- **deps-core**: `locate_value_span`'s empty-value quote correction now keys on the scalar's actual quote style instead of inferring it from the marker byte, fixing a false correction when a Plain/Literal/Folded empty scalar's next token happens to be a quote character; `deps-lsp`'s SHA-pin-comment completion withholding no longer falls through to a package-name registry search (resolves #1184) (#1194)
- **deps-github-actions**: version completion is now withheld once the cursor moves past a full-SHA pin's own ref text, instead of remaining offered inside the trailing tag comment (resolves #1182) (#1185)
- **deps-core**: `locate_value_span`'s empty-value short-circuit now applies the same opening-quote correction as the non-empty path, fixing a one-column-early `version_range` anchor for quoted empty values in deps-dart and deps-gitlab-ci (resolves #1180) (#1185)
- **ci**: `scorecard.yml` and `release.yml` pin `github/codeql-action/upload-sarif` to the current `v4.38.1` digest, resolving stale-dependency code-scanning findings (#1176)
- **deps-go**: fix trailing directive comment (`// indirect`) on a require line with a deleted version being misparsed as the version requirement (resolves #1179) (#1183)
- **deps-gradle**: version-catalog completion now scans single- and double-quoted values as independent delimiters instead of a `"`-only parity check, fixing a wrong context on a mixed-quote-style line and an inline-table field mis-split at a comma inside another field's single-quoted value (resolves #1175) (#1186)
- **ci**: `auto-merge.yml` scopes `contents`/`pull-requests` write permissions to the job instead of the whole workflow, and `SECURITY.md` links the GitHub Security Advisories reporting channel, resolving OpenSSF Scorecard code-scanning findings (#1172)
- **deps-gradle**: DSL scanner's quote-delimiter selection is now scoped to the literal containing the cursor instead of picked line-wide, fixing withheld completion on mixed-quote-style joined lines, a quoted Groovy map key evading the map-notation guard, and a forward-scan range corruption when a trailing comment contains a quote character (resolves #1168) (#1173)
- **deps-gradle**: DSL version completion no longer overspans into a semicolon- or space-joined earlier dependency on the same line (resolves #1160) (#1166)
- **deps-maven**: version completion now triggers inside an empty `<version></version>` tag instead of being silently withheld (resolves #1161) (#1166)
- **deps-pypi, deps-cargo, deps-composer, deps-maven, deps-gradle, deps-nuget**: version-completion's leading-operator stripping fixed for Poetry caret constraints, Cargo `*`, Composer `!=`, and Maven/Gradle/NuGet bracket-range syntax, each ecosystem's operator set now covered by a conformance test (resolves #1137) (#1170)
- **deps-core**: Gradle/Maven version-completion's same-line fallback no longer resolves the wrong dependency when multiple dependencies share one manifest line (resolves #1146) (#1159)
- **deps-core**: version completion now applies the `can_resolve_source` gate for every ecosystem, closing a leak where a private/non-registry dependency's name was still sent to the public registry on every keystroke (resolves #1136) (#1145)
- **deps-cli**: `check` now runs the tier-3 license pre-fetch (Dart, Swift, Gradle, Deno) before evaluating `license_policy`, matching `deps-lsp`'s diagnostics instead of silently missing license data for these ecosystems (resolves #1133) (#1148)
- **deps-cli**: `check` now reports a manifest replaced by an unresolvable or non-file symlink instead of silently skipping it (#1139, resolves #1124)
- **ci**: `crates/github-action`'s entrypoint no longer reports success on an abnormal `deps-cli` exit or an unwritable SARIF path (#1131, #1140)
- **ci**: `crates/github-action`'s entrypoint refuses to write the SARIF file through a symlink or directory left in the scanned checkout (#1132, #1140)
- **ci**: `deps-lsp-check` and `docker-build-and-scan` resolve `deps-cli`'s release tag via an authenticated `gh api` call before the Docker build instead of the Dockerfile's unauthenticated, cache-frozen fallback (resolves #1141, #1144)

## [1.1.0] - 2026-09-16

### Changed
- **Breaking**: `crates/github-action` now packaged as a Docker-based action (`ghcr.io/bug-ops/deps-lsp-github-action`), Trivy-scanned on every PR and before each publish, with a pre-built `deps-cli` instead of a composite `cargo install` wrapper — requires a Linux runner and drops the `version` input (#1126, resolves #1123)

### Added
- **ci**: `crates/github-action` wired into this repo's own `ci.yml` as a SARIF gate, uploading results to Code Scanning and failing the build on a `vulnerable`/`yanked`/`unsatisfiable` policy violation (#1126, resolves #1122)
- **docs**: `.github/codecov.yml`'s per-crate breakdown now uses Codecov components instead of the previous `flags` section (which needed a per-flag CI upload that never happened, so every per-crate flag stayed unpopulated); every `crates/*/README.md` codecov badge now points at its own component, giving actual per-crate coverage visibility from the existing single workspace `lcov.info` upload (#1128)

### Fixed
- **ci**: `crates/github-action`'s Dockerfile now runs `apk upgrade` before `apk add` in both build stages, so the published image no longer ships a stale `alpine:3.22` package layer with an already-patched CVE (`libssl3`/`libcrypto3` CVE-2026-14456, flagged HIGH by Trivy)

## [1.0.1] - 2026-09-16

### Added
- **deps-cli, ci**: pre-built `deps-cli` binaries for all 8 release targets and a new `scripts/install-deps-cli.sh` install script (`curl -fsSL ... | sh`) with checksum verification (#1107)
- **docs**: new mdBook at `book/` reorganizing the former `docs/ECOSYSTEM_GUIDE.md`'s flat feature list into cross-ecosystem, per-ecosystem, and contributor-tutorial chapters, published to GitHub Pages by a new `.github/workflows/mdbook.yml`; `docs/ECOSYSTEM_GUIDE.md` is removed, fully superseded by the book (resolves #1095) (#1096)
- **deps-cli**: `deps-cli check --format sarif` SARIF 2.1.0 output, a `.pre-commit-hooks.yaml` entry, and a `crates/github-action` composite GitHub Action wrapping the SARIF check for `github/codeql-action/upload-sarif` (spec 062 PR 3, resolves #1063, #711) (#1078)
- **deps-cli**: SARIF `tool.driver.rules` entries now get `name`/`shortDescription`, and OSV-advisory rules additionally get `helpUri`/`fullDescription`; results carry `partialFingerprints` and `run.automationDetails.id` (resolves #1077) (#1082)
- **deps-cli**: new `deps-cli check [PATH...]` CLI subcommand — `.gitignore`-aware workspace walk, table/JSON reporting, `--fail-on`/`--offline`/`--cooldown`/`--config` flags, and CI-friendly exit codes (0 clean / 1 policy violation / 2 execution error), reusing `deps-engine`'s classification pipeline with no ecosystem-verdict logic of its own (spec 062 PR 2, resolves #1061) (#1072)
- **deps-core**: new `VulnSeverity::Informational` category for OSV advisories carrying `database_specific.informational: "unmaintained"` (e.g. RUSTSEC unmaintained-crate notices), rendered distinctly from a graded/unscored vulnerability in hover and diagnostics instead of as `"unknown severity"` (resolves #1007) (#1043)
- **deps-gitlab-ci**: mapping-shaped YAML container-anchor support for `include:` entries aliased as a whole mapping (`- *tpl`, `include: *tpl`, `- <<: *tpl`, `- <<: [*a, *b]`), resolved per GitLab's actual Psych merge-key precedence rather than the abstract YAML 1.1 spec (resolves #933, #916) (#1028)
- **deps-core**: promoted `is_plain_null`/`is_null_tag` (originally `deps-dart`-private) into `lsp_helpers`, now shared by `deps-dart` and `deps-gitlab-ci` (#1028)
- **deps-core**: new `quote_scan` module — shared escape-aware string-literal and comment scanning (`ScanSyntax`, `read_string_literal`, `strip_line_comment`, `blank_comments`, `is_code_byte`), now used by `deps-bundler`, `deps-swift`, and `deps-pypi` instead of each hand-rolling its own scanner (resolves #1022) (#1036)

### Changed
- **Breaking (public API)**: **deps-lsp**: `lsp_types_interop` no longer exposes `from_lsp_position`/`to_lsp_position`/`from_lsp_range` (unused outside its own tests), and `to_lsp_uri` now delegates to `deps_core::to_ls_uri` instead of reimplementing the conversion (#1113)
- **deps-core**: migrated restriction-lint `#[allow(...)]` attributes to `#[expect(..., reason = "...")]`, and removed unused dev-dependencies across 8 crates (7 ecosystem crates plus `deps-lsp`) (#1113)
- **docs**: root `README.md` shrunk from a full reference manual back to a pitch-and-getting-started page; editor setup, the configuration option reference, performance benchmarks, project structure, and the `deps-core` versioning policy moved into new/expanded mdBook pages (`book/src/editor-setup.md`, `book/src/configuration.md`, and additions to `book/src/architecture.md`) (#1100)
- **Breaking (public API)**: **deps-core**: `deps_core::policy_config`'s 7 structs are now `#[non_exhaustive]`, with `new()`/`with_*` constructors added where missing; `PolicyConfig::diff` replaces `deps-lsp`'s cross-crate exhaustive-destructuring guard (resolves #1064) (#1093)
- **Breaking (public API)**: **deps-core, deps-engine, deps-lsp, and every `deps-<ecosystem>` crate**: decoupled `deps-core`'s domain model (`Dependency`'s ranges, `ParseResult::uri()`, `Ecosystem`'s `parse_manifest`/`generate_code_actions`/`generate_diagnostics`/`generate_code_lenses`/`generate_document_links`, `LockFileProvider::locate_lockfile`) from `tower_lsp_server::ls_types` — these now use `url::Url` and a new `deps_core::position::{Position, Range}` instead of `ls_types::{Uri, Position, Range}`; `deps-engine`'s own `Cargo.toml` no longer directly depends on `tower-lsp-server` (CI-guarded; it still pulled it in transitively through `deps-core` at the time, which then independently built real LSP response objects unconditionally — closed by #1101 below). LSP-request/response-facing types (cursor positions, `Hover`/`Diagnostic`/`CodeAction`/`WorkspaceEdit`) are unaffected — `deps-lsp` converts at the boundary via a new `lsp_types_interop` module. Version bump deferred to the next release per this project's batching convention (resolves #1071) (#1087)
- **Breaking (public API)**: **deps-core, deps-engine, deps-lsp, deps-cli, and every `deps-<ecosystem>` crate**: `deps-core`'s remaining LSP-response surface (hover/code-actions/code-lenses/inlay-hints/document-links/completions) and its `tower-lsp-server` dependency are now behind a new, non-default `lsp-responses` feature (mirrored per-crate on every ecosystem crate and `deps-engine`); `generate_diagnostics` is retyped to the protocol-agnostic `deps_core::diagnostic::Diagnostic`. `deps-lsp` enables it as before; `deps-cli` never does, so `tower-lsp-server` is no longer reachable from `deps-cli`'s dependency tree at all (CI-guarded), closing the gap #1071 left open (resolves #1083) (#1101)
- **deps-core**: `deps_core::diagnostic::Severity`'s `Deserialize` now clamps an out-of-range integer to the nearest valid severity instead of failing the whole config deserialize, matching `ls_types::DiagnosticSeverity`'s own unvalidated `i32` wire behavior (#1101)
- **deps-engine, deps-lsp**: extracted the ecosystem composition root into a new `deps-engine` crate, re-exported unchanged from `deps-lsp`, plus `EcosystemRuntime::from_policy` — groundwork for `deps-cli`/`deps-mcp` sharing the same registration (resolves #1058) (#1068)
- **deps-engine, deps-lsp**: extracted the pure dependency-classification layer (progress port, in-use-version/lockfile resolution, OSV scan-target and fix-target-verification decisions, registry fetch fan-out, and outcome-merging helpers) into `deps_engine::{progress, classify}`, leaving only editor-specific orchestration (progress lifecycle, staleness guards, cache reconciliation) in `deps-lsp` — groundwork for `deps-cli` sharing identical verdict logic (resolves #1059) (#1070)
- **Breaking (public API)**: **deps-core, deps-lsp**: moved `deps-lsp`'s policy-relevant config sections (diagnostics severities, cache, freshness, supply-chain, registries, network, license policy) into a new `deps_core::policy_config` module, composed back into `deps-lsp::config::DepsConfig` via `#[serde(flatten)]` — the accepted `initializationOptions` JSON shape is unchanged, but `DepsConfig`'s Rust field layout is not: the seven sections moved from top-level fields (`config.diagnostics`, `config.cache`, ...) to `config.policy.diagnostics`/`config.policy.cache`/... External code reading those fields directly (not just via JSON) will not compile until updated; groundwork for the upcoming `deps-cli` (#711). Version bump deferred to the next release per this project's batching convention — see `specs/062-cli-check-mode/plan.md` §10 (#1056)
- **deps-core, deps-dart, deps-github-actions, deps-gitlab-ci, deps-npm**: bumped `yaml-rust2` 0.12 -> 0.13 (upstream MSRV-only `encoding_rs` pin fix, no API/behavior change) and disabled its unused default `encoding` feature, dropping a duplicate `encoding_rs 0.7.2`/`cfg-if 0.1.10` that the new upstream pin would otherwise have pulled in alongside the already-used `encoding_rs 0.8.40` (resolves #923) (#1033)
- **ci**: moved `Cross.toml` to `.github/Cross.toml` to declutter the repo root; `cross` steps now set `CROSS_CONFIG` explicitly since `cross` only auto-discovers a root-level file (#1015)
- **CI**: split the `feature-matrix` job's test execution into a separate `feature-matrix-test` job so it runs in parallel with the clippy/lint checks instead of sequentially on one runner (#1018)
- **CI**: `feature-matrix-test` now shards across a 4-leg matrix and drops the redundant `--features default` slice (identical coverage to `--all-features`), cutting its wall-clock time from ~10m47s to an expected few minutes (resolves #1030) (#1031)
- **deps-core, deps-gitlab-ci, deps-github-actions, deps-npm**: consolidated `deps-gitlab-ci`/`deps-github-actions`/`deps-npm`'s near-duplicate `DashMap` eviction helpers into `deps_core::cache_policy::evict_arbitrary_if_full`/`evict_expired_then_clear_all` (resolves #996) (#1024)
- **deps-core, deps-gitlab-ci, deps-nuget**: consolidated `deps-gitlab-ci`/`deps-nuget`'s near-duplicate salted credential-digest helpers into `deps_core::secret::digest_salt`/`auth_digest` (resolves #1003) (#1024)
- **deps-gitlab-ci**: a literal inline `<<: {...}` merge key (no anchor/alias involved) now folds into the `include:` entry, matching GitLab's actual YAML loader — previously `<<` was treated as an unrecognized key and silently ignored (#1028)
- **deps-gitlab-ci**: an empty/null-like `ref:` on an ordinary, anchor-free `include:` entry now ships no version at all, instead of `version_req = Some("")` with a zero-width range (#1028)
- **deps-core, deps-dart**: `is_plain_null` now recognizes `Null`/`NULL` in addition to `~`/`null` — the four spellings GitLab's Psych YAML loader treats as null (#1028)
- **deps-bundler**: `extract_group`/`extract_source`/`extract_platforms`/`extract_require` now take the same `&[(&str, usize)]` slice as `extract_version`, dropping a redundant per-gem `Vec` allocation in `finalize_pending_gem` (resolves #1023) (#1036)
- bumped `rustls` 0.23.44 -> 0.23.45 (RUSTSEC-2026-0285: TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries) (#1036)
- **CI**: `cargo-semver-checks` is advisory-only on PR/push again (was a blocking gate since #945), reverted after it blocked a routine bug-fix PR over an incidental non-breaking `#[must_use]` addition; the weekly scheduled sweep still hard-fails and tracks genuine breaks (resolves #1048) (#1049)
- **deps-engine, deps-lsp, ci**: closed `deps-lsp`'s last direct dependency on `deps-gitlab-ci` via a new `deps_engine::setup::validate_gitlab_instance_host`, and added a CI guard asserting no ecosystem crate is a *direct* non-dev dependency of `deps-lsp`/`deps-cli` (resolves #1073) (#1079)
- **docs**: mdBook now publishes to the GitHub Pages site root (`https://bug-ops.github.io/deps-lsp/`) instead of `/book/`; `mdbook.yml`'s now-dead `workflow_run` trigger for the removed `Documentation` workflow is also dropped (#1098)
- **CI**: `mdbook.yml` now deploys via the native GitHub Actions Pages flow (`actions/configure-pages`, `actions/upload-pages-artifact`, `actions/deploy-pages`) instead of `peaceiris/actions-gh-pages` pushing to a `gh-pages` branch, matching the repo's Pages source now being set to "GitHub Actions" (#1099)
- removed redundant in-code `//` comments that merely restated adjacent code across every crate; issue-referenced and invariant-documenting comments are untouched (no functional change) (#1102)

### Removed
- **CI**: removed the legacy `Documentation` workflow (`.github/workflows/docs.yml`), which deployed `cargo doc` output to the `gh-pages` root with `force_orphan: true` on every Rust-touching push, wiping the mdBook site published by `mdbook.yml` (#1096) each time it ran (#1097)
- **CI**: removed the `wasm` job — it built `crates/deps-zed`'s WASM target, but `deps-zed` is a separate git submodule with its own repository and CI; verifying it here duplicated work that belongs there (#1102)

### Fixed
- **deps-cli**: `check`'s directory walk no longer silently skips a manifest reachable only through a symlink; it is now reported via a warning by default, or resolved and scanned with the new opt-in `--follow-symlinks` flag (#1125, resolves #1112)
- **ci**: `release.yml` now builds `deps-lsp` and `deps-cli` in separate cargo/cross invocations, preventing cargo's feature-unification from linking `tower-lsp-server` into the released `deps-cli` binary (#1110, resolves #1103)
- **deps-cli**: `check` no longer trusts the scanned repository's own `.gitignore`/`.ignore` files by default — an attacker-controlled ignore rule could previously hide a vulnerable manifest from a CI security gate with no warning and exit 0; `--respect-gitignore` restores the old ignore-aware behavior and now warns when it silently drops a manifest-shaped exclusion (resolves #1109) (#1111)
- **deps-cli**: `check`'s manifest walk no longer silently drops every relative root, including its own default (`.`) — walked roots are now absolutized before routing, and any remaining URI-conversion failure surfaces as a warning instead of a silent drop (resolves #1108) (#1111)
- **deps-cargo, deps-nuget, deps-pypi, deps-lsp, deps-npm, deps-gradle**: client-supplied manifest/document URIs with a non-`file:` scheme or remote host no longer resolve against the real filesystem, including a Windows-only bypass where a `file:` URI's host was silently stripped by URL parsing when the path looked like a drive letter (resolves #1090) (#1091)
- **CI**: new blocking `fuzz-check` job runs `cargo check --workspace` against the independent `fuzz/` cargo-fuzz workspace on every PR touching Rust code, closing a gap where an `Ecosystem`/`parse_*` signature change could silently break fuzz harnesses undetected until the slow, non-blocking weekly `fuzz` job caught it (resolves #1088) (#1092)
- **deps-core, deps-nuget**: `deps_core::lockfile::locate_lockfile_for_manifest` and `deps-nuget`'s multi-project lock file fallback no longer resolve a non-`file:` or remote-host manifest URI against the real filesystem, via a new shared `deps_core::lockfile::resolve_manifest_file_path` guard (resolves #1084, #1085) (#1089)
- **deps-gitlab-ci**: an alias to a null-like scalar anchor (e.g. `ref: *e` where `&e` is empty/`~`/`null`/`Null`/`NULL`) now ships no version, matching how a literal null-like `ref:` is already handled (resolves #1029) (#1081)
- **deps-cli**: `.pre-commit-hooks.yaml`'s `deps-lsp-check` hook now uses `language: system` instead of `language: rust`, which could never install from this repository's virtual workspace root; the hook can now be referenced remotely (`repo: https://github.com/bug-ops/deps-lsp`) as long as `deps-cli` is already on the consumer's `PATH` (resolves #1074) (#1080)
- **deps-cli**: SARIF `ruleId` is now the underlying diagnostic code (e.g. an OSV advisory id) when one exists, instead of always collapsing to the coarser `Category` token, so distinct advisories no longer share one GitHub code-scanning rule (resolves #1075) (#1082)
- **deps-core**: `is_valid_osv_id` now rejects a bare `.`/`..` advisory id (an RFC 3986 dot-segment that a lone character-class allowlist does not catch), closing a link-retargeting risk in `Advisory::url`, hover markdown, and `Diagnostic.code_description`; a new `deps_core::osv::validated_osv_url` is the single validated construction path for that URL, also reused by `deps-cli`'s SARIF `helpUri` (resolves #1077) (#1082)
- **deps-cargo, deps-go, deps-npm, deps-pypi**: the version-completion cap test now mocks more versions than the cap and asserts the exact `MAX_COMPLETION_VERSIONS` count instead of a vacuous `<= 20`; a deps-go doctest tautology and two unverified pypi mocks are fixed the same way (resolves #1066) (#1067)
- **deps-npm, deps-pypi**: the package-name search and position-based version completion tests now run against mocked registry endpoints instead of the live registry, and assert real completion items instead of a tautological `is_empty() || !is_empty()` check (resolves #1055) (#1065)
- **deps-cargo**: the package-name search completion test now runs against a mocked crates.io search API instead of the live registry, and asserts a real completion item instead of a tautological `is_empty() || !is_empty()` check (resolves #1052) (#1054)
- **deps-cargo**: unknown-package completion tests now run against a mocked crates.io sparse index instead of the live registry, so a network outage or a real zero-request regression no longer passes vacuously (resolves #1045) (#1051)
- **deps-npm, deps-pypi, deps-deno, deps-bundler, deps-dart**: unknown-package completion tests now run against a mockito server instead of the live registry, so a network outage or a real zero-request regression no longer passes vacuously (resolves #1038) (#1044)
- **deps-core**: `HttpCache::cache_key` no longer collapses an unauthenticated `Pinned`-tier fetch and an authenticated one whose credential digest happens to hash to `0` onto the same cache key (resolves #1025) (#1035)
- **CI**: the `cross-check` job's i686 leg now builds and tests natively via `gcc-multilib` on `ubuntu-latest` instead of through `cross`'s musl Docker container, dropping the associated apt-get/Docker overhead and the `--test-threads=1` workaround (now uses `cargo nextest`) (#1027)
- **CI**: `cargo-semver-checks` is now a blocking gate on PR/push and part of `ci-success` (was advisory-only, milestone criterion B3) (resolves #945) (#1012)
- **deps-bundler**: multi-line `gem` declarations (continuation-line `:source =>`/`source:`, backslash continuation, or a commented-out option) no longer leak private gem names to the public rubygems.org registry, and the parser's block/group state tracking is now O(1) per line instead of O(block depth) (resolves #991, #1009) (#1016)
- **deps-bundler**: a `source ... do` block URL containing Ruby string interpolation with a nested single-quoted literal (e.g. `ENV['CREDS']`) now still opens the block instead of silently leaking its gems to the public registry (resolves #1019) (#1040)
- **deps-bundler**: a multi-line `gem` call whose continuation opens an array/hash literal (e.g. `platforms: [`) instead of ending in a trailing comma is now tracked as open until the literal closes, so a later option on the same call is no longer dropped (resolves #1017) (#1040)
- **deps-bundler**: a parenthesized `gem(...)` call, at the top level or nested inside a block, is now recognized as a dependency instead of silently producing no diagnostic, hover, or completion (resolves #1021) (#1040)
- **deps-lsp**: gated 4 tests that panicked (not just failed to compile) under a reduced ecosystem feature set, and fixed the crate's remaining unused-import/dead-code warnings across the feature matrix; CI now lints deps-lsp's test targets with `-D warnings` and runs `cargo hack nextest run -p deps-lsp --each-feature` on every individual feature (resolves #1005, #1001) (#1011)
- **docs**: corrected README.md's and ECOSYSTEM_GUIDE.md's contradictory `license_policy` diagnostic ecosystem-scope claims — the diagnostic actually fires for five ecosystems (Composer, Dart, Swift, Deno, Gradle), not "all 14" or the previously listed four (resolves #1004) (#1013)
- **deps-go**: `test_generate_code_actions_on_module` now runs against a mockito server instead of live `proxy.golang.org`, removing an intermittent CI failure (resolves #1014) (#1032)
- **deps-bundler**: `source:`/`git:`/`path:`/`github:` inline option values no longer truncate at an embedded quote of the opposite kind (e.g. an escaped or unescaped `'` inside a `"`-delimited value) (resolves #1020) (#1036)
- **deps-go**: `test_get_versions_from_plain_registry_source_unchanged`, `test_complete_versions_unknown_package`, and `test_generate_hover_on_module_path` now run against a mockito server instead of live `proxy.golang.org` (resolves #1034) (#1037)
- **deps-bundler**: `deps_core::quote_scan`'s fallback pass for Ruby string interpolation is now nested-quote-aware, no longer mis-terminating on a cross-type nested string containing `}` before the outer quote closes (resolves #1047) (#1057)
- **deps-bundler**: `deps_core::quote_scan`'s fallback pass no longer mistakes an apostrophe inside a Ruby `%`-literal (`%r|'|`, `%w[a'b]`, ...) or a `#` line comment for a string-opening quote, closing a residual leak vector past nested-quote-awareness (resolves #1060) (#1069)
- **deps-core**: `capture_tracing_output`/`_at`/`_async`/`_async_at` no longer silently return empty output when an untraced sibling test touches the same tracing callsite first under a shared-process test run (resolves #1006) (#1042)
- **deps-bundler**: inline option values with same-quote Ruby string interpolation (e.g. `source: "https://#{ENV["TOKEN"]}@..."`) no longer truncate or leak a private source to the public registry (resolves #1041) (#1046)
- **deps-pypi**: a requirements `-r`/`-c` document-link target is no longer resolved when it's an absolute path (POSIX, or any Windows drive-letter/drive-relative form) — workspace-root containment for `../`-escape targets is also implemented but stays dormant until pypi gains workspace-root discovery (resolves #937) (#1050)
- **deps-bundler, deps-core**: closed residual private-source-leak vectors in malformed-Gemfile parsing without regressing legitimate multi-line/parenthesized `gem(...)` calls (resolves #1039) (#1053)

## [1.0.0] - 2026-09-14

First stable release. Of the six original "1.0.0 stabilization" milestone entry criteria, B1, B5,
B6, and the `constitution.md` post-1.0 policy update are done, along with the emergent
feature-matrix follow-ups (#975, #998, #1000). Three criteria are consciously waived rather than
met, all decided 2026-09-14 during release prep:

- **B2** (one full minor cycle with zero pre-1.0 Breaking entries): not met — this cycle still
  carries two pre-1.0 breaking changes (see Removed, below).
- **B3** (`cargo-semver-checks` as a blocking CI gate): not met — the `semver` CI job remains
  `continue-on-error` on PR/push and is not part of `ci-success`. Issue #945 had been closed
  `NOT_PLANNED` with no decision recorded; reopened to track this as a post-1.0 follow-up.
- **B4** (decision on `reqwest`/`yaml_rust2`/`tower-lsp-server`/`semver::VersionReq` leaking into
  `deps-core`'s public API): not met — `deps-core` still re-exports all three crates and
  `deps-gitlab-ci` still returns `semver::VersionReq` directly, with no accept/wrap/feature-gate
  decision implemented. Issue #851 had also been closed `NOT_PLANNED` with no decision recorded;
  reopened to track this as a post-1.0 follow-up.

From this release onward, `specs/constitution.md` principle 8's post-1.0 breaking-change policy
(major version bump per crate, a labeled "Breaking" CHANGELOG entry, `cargo-semver-checks` as the
CI catch-net once B3 actually lands) is in effect.

### Added
- **deps-core**: `LockFileCache::with_capacity` and `DEFAULT_MAX_CACHED_LOCKFILES` — a custom-capacity constructor and the new default entry-count bound (resolves #962) (#971)

### Changed
- **deps-core**: consolidated `github`/`deps_dev`/`osv`'s near-identical bounded-`DashMap` eviction policies and duplicated `CACHE_EVICTION_PERCENTAGE` constant into a shared `cache_policy` module (resolves #977) (#995)
- **deps-core, deps-pypi, deps-npm, deps-go, deps-nuget**: consolidated four near-identical validated-registry-URL newtypes into one generic `deps_core::net_policy::ValidatedRegistryUrl<K>` plus a shared `InvalidEntry<E>` (deps-cargo excluded, see spec D1) (resolves #959) (#974)
- **deps-core, deps-cargo, deps-npm, deps-pypi, deps-nuget, deps-go**: extended `impl_parse_result!` with a `blocked_registries` arm and extracted the duplicated bounded alternate-registry-map insertion (`MAX_ALTERNATE_REGISTRIES`, vacant/occupied `DashMap::entry` handling) into shared `deps_core::registry::register_capped`/`register_capped_with_occupied` helpers, keyed to a `KeyShape` (`Url`/`Opaque`) so a hashed routing key is never mistaken for a redactable URL; the cap-reached `tracing::warn!` field is now uniformly `key` (was `index` for Cargo/npm) and its message uniformly ends "not registering a new entry" (resolves #969, #976) (#984)
- `specs/constitution.md`: rewrote principle 7 with a post-1.0 breaking-change policy (major-bump-per-crate, a labeled "Breaking" changelog entry, `cargo-semver-checks` as the CI catch-net) alongside the existing pre-1.0 clean-break rule (resolves #948) (#957)
- **deps-core, deps-cargo, deps-pypi, deps-gradle, deps-nuget, deps-deno, deps-swift, deps-bundler, deps-go, deps-maven**: routed every remaining byte-span-to-`Range` site through `deps_core::lsp_helpers::byte_span_to_range` instead of a per-crate hand-rolled duplicate (resolves #927) (#950)
- **deps-dart**: migrated `pubspec.yaml` parsing's `RawField`/`field_range` onto `deps_core::lsp_helpers::MarkedScalar`, the same shared position-tracking type `deps-github-actions`/`deps-gitlab-ci` already use (resolves #928) (#950)
- **deps-core, deps-pypi, deps-deno, deps-npm, deps-go**: extracted the byte-identical `404`-to-`PackageNotFound` mapper into `deps_core::not_found_or` (resolves #929 item 1) (#950)
- **deps-core, deps-dart, deps-composer, deps-nuget, deps-npm**: extracted the shared warn-and-error boilerplate behind each ecosystem's own dot-segment guard into `deps_core::lsp_helpers::dot_segment_rejection_error`, leaving every crate's own segmentation predicate untouched (resolves #929 item 2) (#950)
- **deps-core, deps-dart, deps-gitlab-ci**: extracted the duplicated bounded YAML scalar-anchor value tables into a shared `deps_core::yaml_anchor::ScalarAnchorTable`/`AnchorLimits` (resolves #942) (#954)
- **deps-core, deps-dart, deps-github-actions, deps-gitlab-ci**: extracted the three YAML `MarkedEventReceiver` parsers' hand-rolled frame-stack state machines into a shared, generic `deps_core::yaml_walk::FrameStack` plus `lsp_helpers::MarkedScalar`/`byte_span_to_range` helpers (resolves #908) (#921)
- **deps-core**: `LineOffsetTable` is no longer `Sync` (still `Send`) — build one per document parse, do not share across threads (#888)
- **deps-core**: unified `net_policy`'s duplicated userinfo-redaction carve-out rules into one shared `redact_credential` scanner — zero behavior change (resolves #846) (#863)
- **deps-core, deps-cargo, deps-go, deps-lsp**: documented the exhaustive/non_exhaustive justification for 8 public enums per `deps-core`'s API-stability policy; `HostClass` and `deps_lsp::document::DocumentState` are now `#[non_exhaustive]` (resolves #854) (#867)
- `specs/`: reconciled `MOC-specs.md` against actual issue/PR state — stale "draft" spec rows marked shipped with their PR/issue references, all shipped specs moved into a "Completed Specs" section, and `specs/constitution.md` added (resolves #855) (#867)

### Removed
- **Breaking (pre-1.0, public API)**: **deps-core**: removed `LockFileProvider::is_lockfile_stale` (the trait method had no callers outside its own conformance tests); added direct unit-test coverage for `LockFileCache::get_or_parse`'s actual staleness comparison instead (resolves #926) (#943)
- **Breaking (pre-1.0, public API)**: **deps-core**: removed the unused `severities: DiagnosticSeverities` parameter from `Ecosystem::generate_code_lenses` — the override it was added for was deleted, and no other override ever read it (resolves #930) (#951)

### Fixed
- **deps-core**: `fs_probe`'s snapshot helpers and 16 tracing-capture tests (`registry`, `pagination`, `github`, `mtime_cache`) now compile under a reduced feature set without `test-util`, matching #998's fix for `deps-lsp` (resolves #1000) (#1008)
- **deps-lsp**: `lib.rs`'s `#[cfg(test)]` module now compiles under any reduced ecosystem feature set; CI's feature-matrix job gained a dedicated `cargo hack check -p deps-lsp --each-feature --all-targets` step to catch this class of regression (resolves #998)
- **deps-swift**: a non-GitHub-host registry-form `Package.swift` dependency no longer surfaces the misleading "Invalid package name... must be a GitHub 'owner/repo' identifier" diagnostic; version resolution is silently skipped for it instead, matching `deps-github-actions`'s existing non-resolvable-source handling (resolves #983) (#994)
- **deps-swift**: fixed a `version_req`/fixture-content mismatch in the ignored completion-dispatch test that made it exercise the wrong code path when run manually (resolves #924) (#994)
- **deps-core**: blocked-registry diagnostics no longer skip userinfo redaction on `declaration_key` for a scheme-colon slash-less or opaque-label-prefixed credential shape that a bare `"://"` substring check missed (resolves #981) (#992)
- **deps-bundler**: hash-rocket per-gem options (`:source =>`, `:git =>`, `:path =>`, `:github =>`) are now recognized, closing the same registry-name-leak class as #980 for Ruby's older Gemfile syntax (resolves #987) (#989)
- **deps-bundler**: hash-rocket `:group =>`, `:require =>`, and `:platforms =>` per-gem options are now recognized, closing the remaining #987 gap left by #989's four other options (resolves #990) (#999)
- **deps-bundler**: a version constraint followed by a trailing comment (`gem "rails", "~> 7.0" # ...`) is no longer dropped from hover/diagnostics (resolves #988) (#989)
- **deps-lsp**: fixed 3 rustc warnings (`register_ecosystems`) that only surfaced under a reduced ecosystem feature set; CI now runs `cargo hack clippy --workspace --each-feature` in a dedicated job to catch this class of regression on every PR (resolves #975)
- **deps-swift**: `Package.swift`/`Package.resolved` dependencies on a non-GitHub host are no longer coerced into an attacker-nameable GitHub `owner/repo` identity queried with the user's `GITHUB_TOKEN`; they now stay visible as a non-resolvable Git source under their raw URL (resolves #979) (#982)
- **deps-bundler, deps-dart**: gems behind a Gemfile `source ... do` block or inline `source:` option, and `hosted:` pubspec dependencies, are now classified as a custom registry instead of being queried against rubygems.org/pub.dev (resolves #980) (#986)
- **deps-gitlab-ci**: a GitLab instance host blocked by `registries.workspace_registries` policy (via `registries.gitlab_instance_host` or an inline `component:` host) now surfaces the shared blocked-registry informational diagnostic naming the blocked host class, instead of the misattributed "set `registries.gitlab_instance_host`" message, matching `deps-cargo`/`deps-npm`/`deps-pypi`/`deps-nuget`'s existing behavior (resolves #967) (#973)
- **deps-nuget**: a plain (non-mapping) source chain declaring two or more independently blocked feeds now reports every one of them as its own diagnostic, instead of only the first found (resolves #965) (#972)
- **deps-core, deps-nuget, deps-npm, deps-pypi**: `blocked_class_for`'s internal `(HostClass, String, String)` result is now the named `deps_core::BlockedSourceClass` struct, closing the same raw-value/declaration-key field-swap risk `BlockedRegistryOccurrence` was already converted off of (resolves #966) (#972)
- **deps-nuget, deps-core, deps-cargo, deps-npm, deps-pypi**: fixed four #925 follow-up gaps in blocked-custom-registry-host detection — NuGet's plain-chain and mapping-shaped source branches no longer mask a blocked host behind a coexisting valid or earlier-invalid source, Cargo/npm/PyPI dependencies sharing a blocked-registry declaration each keep their own visible diagnostic via bounded `related_information`, and `ParseResult::blocked_registries()` now returns a named struct instead of a positional 4-tuple (resolves #944) (#964)
- **deps-core**: `LockFileCache` is now bounded (256 entries by default) with least-recently-parsed eviction, and its lock file discovery/read now run entirely on the blocking-thread pool instead of the calling tokio worker (resolves #962, #963) (#971)
- **deps-dart**: removed flaky wall-clock-ratio assertions from three `pubspec.yaml` parser tests and replaced them with deterministic correctness checks, plus a new `dart_benchmarks` criterion suite to observe scaling behavior locally (resolves #946) (#953)
- **deps-core**: version-completion dropdown and code-action "update version" quick-fix now source their `(latest)` label/preselection from the same registry-delegated pick hover already uses, instead of raw fetch-order index 0 or a re-derived `is_stable()` scan — fixes mislabeling a pre-release or a newer deprecated release as latest (resolves #952, sibling of #313) (#955)
- **deps-core**: the completion dropdown and code-action quick-fix no longer silently drop the `(latest)` marker when the registry-selected version falls outside the 5-entry raw-order display window — it is now bumped into the displayed window instead (resolves #956) (#960)
- **deps-core**: hover's "Recent versions" list no longer silently drops the `(latest)` marker when the registry-selected pick falls outside the 8-entry raw-order display window — it is now bumped into the displayed window instead, matching completion/code-actions' #956 fix (resolves #961) (#970)
- **deps-npm, deps-pypi, deps-nuget**: a dependency whose custom-registry resolution is blocked by `registries.workspace_registries` policy now surfaces an informational diagnostic on its own line, matching `deps-cargo`'s existing behavior, instead of degrading silently to the public registry with no trace (resolves #925) (#949)
- **deps-go**: a `GOPROXY` hop blocked by `registries.workspace_registries` policy now surfaces a single informational diagnostic per document, instead of only a `tracing::warn!` with no editor-visible trace (resolves #958) (#968)
- **deps-gitlab-ci**: an alias key (`*k: value`) whose resolved anchor text matches a recognized `include:`-entry field name is now reinterpreted as that key, the same as a literal key (resolves #942) (#954)
- **deps-core**: `DependencySource`'s `Debug` impl now redacts URL-bearing variants (`Git`, `Url`, `CustomRegistry`, `AlternateRegistry`) via `RedactedUrl` instead of printing them raw, closing a credential leak reachable through any `tracing::warn!(?source, ...)` call site (resolves #935) (#938)
- **deps-core, deps-lsp**: redacted two more credential-leak sinks in the same family — `RegistriesConfig`'s debug dump of `gitlab_instance_host` and the blocked-registry diagnostic's raw index value (resolves #936) (#938)
- **deps-maven**: `compare_versions` no longer panics `Vec::sort_by` on a `maven-metadata.xml` version list mixing zero-digit-prefixed qualifiers (e.g. `0ga`) with their bare/aliased spellings (resolves #934) (#940)
- **deps-gradle**: fixed a total version-completion regression from #922 — compact GAV coordinates and version catalog entries returned zero completions because their detected range was never wired to the literal's real byte span (resolves #931) (#939)
- **deps-gitlab-ci**: a scalar YAML anchor used as `ref:`/`project:`/`component:` and aliased elsewhere in the same file's `include:` subtree is now recognized, with hover/diagnostics/inlay hints at the alias site and SHA-pin quickfixes/version completion withheld there (resolves #912) (#941)
- **deps-core, deps-maven, deps-gradle, deps-swift**: version completion no longer splices text into non-literal version spans (unresolved property/variable interpolation, YAML aliases, Swift version ranges) (resolves #919) (#922)
- **deps-github-actions, deps-gitlab-ci**: an explicit complex YAML key (`? <mapping>`/`? <sequence>`) no longer desyncs the enclosing mapping's key/value parsing, matching `deps-dart`'s existing handling (resolves #908) (#921)
- **deps-github-actions**: SHA-pinned `uses:` refs with a partial `# vX`/`# vX.Y` comment tag now get inlay hints/diagnostics, using the registry-confirmed tag over the comment when available (resolves #907) (#914)
- **deps-dart**: fixed `is_plain_null` mishandling an explicit YAML tag (including the verbatim null-tag form) and moved `DependencyBudget` enforcement before entry construction; pinned six behavior changes from #903's parser rewrite with regression tests (resolves #906) (#911)
- **deps-dart**: aliasing a whole dependency section or `environment:` mapping via a YAML anchor now resolves correctly instead of silently losing its data (resolves #905) (#910)
- **deps-dart**: fixed unbounded `O(N x document length)` scans in the pubspec.yaml parser by rewriting position tracking onto `yaml-rust2`'s event API (resolves #899) (#903)
- **deps-core**: `net_policy::redact_userinfo` now scans the path/query of a host-having URL with empty userinfo for a credential-shaped segment instead of returning it verbatim, closing a leak reachable via a `c:/`-corrupted or slash-less authority (resolves #901) (#902)
- **deps-github-actions**: `extract_comment_tag` no longer mis-attributes a flow-style line's trailing comment to an unrelated SHA-pinned ref, which could corrupt YAML on version-update code action acceptance (resolves #898) (#900)
- **deps-core**: `net_policy::segment_has_credential_colon` no longer takes `O(n^2)` time on a drive-letter-dense run, the same unguarded-scan pattern #893/#894 fixed in `colon_credential_match_seeded` (resolves #896) (#900)
- **deps-core**: `net_policy`'s credential redaction no longer takes `O(n^2)` time on input alternating `[` with a non-colon byte, the sibling case #893's consecutive-`[` fix left open (resolves #894) (#895)
- **deps-core**: `net_policy`'s credential redaction no longer takes `O(n^2)` time on a run of consecutive `[` characters (resolves #891) (#893)
- **deps-github-actions, deps-core**: fixed a quadratic-time parsing regression on single-line manifests with many ref-pinned GitHub Actions dependencies (resolves #885) (#897)
- **deps-core**: `net_policy::redact_authority_suffix` now redacts a colon-only credential sitting in the window between two already-masked `@`-shaped decoys instead of emitting it verbatim (resolves #886) (#890)
- **deps-core**: `net_policy::redact_userinfo` now redacts a colon-less `TOKEN@host` credential reachable only through `redact_authority_suffix`'s widen branch (e.g. behind an unclosed `[` that fails `Url::parse`), previously returned verbatim (resolves #887) (#892)
- **deps-core**: fixed O(N^2) hover/diagnostics/completion latency on manifests with a dependency value on a non-ASCII line (resolves #882) (#888)
- **deps-core**: `net_policy::redact_userinfo` now redacts token-prefixed username-only credentials in opaque-path values (resolves #858) (#889)
- **deps-core**: `net_policy`'s credential-redaction fallback (`redact_authority_suffix`/`redact_colon_credential`) now keeps scanning past an already-masked `@`-shaped or colon-only credential instead of stopping at the first match, closing three leak gaps with no `O(n²)` regression (resolves #870, #873, #874) (#881); #875 remains open as a separate, narrower residual gap.
- **deps-core, deps-github-actions, deps-gitlab-ci**: workflow/GitLab CI YAML `uses:`/`ref:`/`project:`/`include:` references after a block scalar (`|`/`>`) containing a non-ASCII character no longer vanish from hover/diagnostics/completion/code lens — upstream `yaml-rust2`'s `Marker::index()` desyncs from a true byte offset inside such block scalars; resolution now uses `Marker::line()`/`col()` instead (resolves #879) (#883)
- **deps-core**: `net_policy::redact_userinfo` now anchors on the first (not nearest) `://` preceding a credential, so a credential behind multiple stacked scheme separators is no longer left unredacted (resolves #871) (#877)
- **deps-core**: fixed a `net_policy::redact_userinfo` scan-anchor bug that let a later `://`/`@`/`?`/`#` boundary hide a leaked credential in tracing/error output (resolves #862) (#TBD); residual known gaps tracked separately as #870, #873, #874, #875 (a gate for #875 was tried and reverted — it traded a P4 cosmetic over-redaction for a real credential-leak regression).
- **deps-core**: `net_policy::redact_userinfo`/`url_for_tracing` now redact a second, independent colon-shaped credential sitting after an already-masked userinfo `@` instead of leaving it untouched (resolves #869) (#872)
- **deps-core**: `net_policy::url_for_tracing` now truncates the query string/fragment before redacting, so a credential-shaped `@` inside the query can no longer swallow the `?`/`#` boundary and leak the rest of the query unredacted (resolves #866) (#872)
- **deps-core**: `net_policy::redact_userinfo` now fully redacts an `@` embedded inside a password for opaque-path (`scheme:/path`) values, closing a partial credential leak (resolves #859) (#865)
- `fuzz/redact_userinfo`: fixed a false-positive crash where the fuzzer-controlled host/port tail could coincidentally reproduce the sentinel literal, tripping the leak assertion outside any credential; no `net_policy` behavior change (#864)
- **deps-core**: `net_policy`'s bracketed-IPv6-host carve-out no longer silently exempts a credential sitting next to a `[...]` host literal (resolves #860)
- **deps-core**: `redact_userinfo`'s opaque-path fallback no longer disables credential redaction for an unrelated `@` elsewhere in the value (resolves #857)

## [0.14.0] - 2026-09-11

### Added
- **deps-core**: re-export `tower_lsp_server`; document tower-lsp-server/deps-core version coupling (resolves #832) (#839)
- **deps-core**: `RedactedUrl` structural chokepoint and `SanitizedRegistryError` wrapper for outbound-URL redaction, migrated across every internal call site, with a regression test pinning the source-chain redaction (partial work on #789) (#800)
- **deps-core**: `registry_conformance!`/`formatter_conformance!` macro family (compile-time proof that `Registry`/`EcosystemFormatter` methods are true inherent methods, not just trait-reachable) rolled out across all 14 ecosystem crates, plus a formatter template fix (resolves #784, #785) (#787)
- **workspace**: CI gained a `semver` job (cargo-semver-checks) guarding against accidental public-API breaks; `#[non_exhaustive]` added to the highest-churn public error/dependency/version types as a first pass (resolves #755) (#768)
- **deps-lsp, deps-core**: `tracing::instrument` spans on LSP request handlers, the registry HTTP/cache layer, document lifecycle handlers, background fetch-task spawning, and every ecosystem registry fetch entry point, correlating log events by request/document/ecosystem/package (resolves #756, #671) (#766) (#677)
- `fuzz/` workspace: cargo-fuzz targets for fallback-completion scanners, GitHub Actions/GitLab CI/Dart/pnpm YAML parsing, the shared TOML/YAML/JSON depth checkers, JSONC position recovery, and the Maven/NuGet manifest and registry-response XML parsers, plus `proptest` coverage for the depth checkers and a bounded nightly-toolchain CI job (resolves #740, #727, #691) (#745) (#735) (#678) (#694)
- **README**: editor setup snippets for Emacs (`eglot`, `lsp-mode`), Sublime Text LSP, Kate, and coc.nvim (partial work on #712) (#717)
- **deps-github-actions**: `action.yml`/`action.yaml` composite/Docker/JS action manifests (repository root or `.github/actions/<name>/`) now get the same hover, diagnostics, SHA-pin quick fix, and code lens as workflow files (resolves #706) (#718)
- **deps-npm**: `pnpm-lock.yaml` is now read as a lock file for in-use/resolved-version detection, aggregating every pnpm workspace importer, with `package-lock.json` retaining precedence when both are present (resolves #709) (#719)
- **deps-core, deps-composer**: hover now shows the SPDX license for the resolved and latest version (Cargo, npm, PyPI, Go, Maven, Bundler, NuGet, Composer), flagging a "License changed" when they differ (resolves #204) (#663)
- **deps-dart, deps-swift, deps-gradle, deps-deno, deps-core, deps-lsp**: license hover extended to Dart/Swift/Gradle/Deno via background pre-fetch (with a "(detected)" qualifier for Dart's pana-scored result), plus a new `initializationOptions.license_policy: { allow?, deny? }` setting producing an SPDX allow/deny-list diagnostic evaluated consistently across every diagnostics path (resolves #660, #661) (#682)
- **deps-core**: Gradle's free-text Maven Central POM license names are now normalized to SPDX identifiers and re-enter `license_policy` evaluation instead of being unconditionally excluded (resolves #679) (#685)
- **deps-core**: OSV malicious-package advisories (`MAL-*` id or alias) now classify as a distinct `VulnSeverity::Malicious` instead of falling through to "unknown severity" (resolves #646) (#652)
- **workspace**: clippy restriction lints (`indexing_slicing`/`unwrap_used`/`expect_used`/`string_slice`) plus deps-core's `cast_*` truncation lints enforced across all 16 crate roots, as a regression gate against panic-DoS bugs in request-path parsers (resolves #673, #676, #680, #683) (#686)
- **deps-core**: `EcosystemId::ALL` (derived from the same variant list backing `id()`/`FromStr`) and a new `deps_core::conformance` module (5 macros, behind `test-util`) generating the shared per-crate conformance test family every ecosystem crate previously hand-copied, rolled out to all 14 ecosystem crates, plus a `package_url` hostile-input-safety check and `no_lockfile_support`/`format_version` macro arms (resolves #758, #782) (#776) (#781) (#786)
- **deps-bundler, deps-cargo, deps-composer, deps-dart, deps-go, deps-maven, deps-npm, deps-nuget, deps-pypi, deps-swift**: migrated onto `registry_conformance!` (14/14 crates, was 4/14) and extended `completion_guard_conformance!` to Maven/Swift (11/14) (resolves #794) (#805)
- **workspace**: CI's `security` job now runs `gitleaks` against `.gitleaks.toml`, wiring up previously-dead secret-scanning config (resolves #825) (#840)

### Fixed
- **deps-lsp, deps-core, deps-deno, deps-dart, deps-swift, deps-maven, deps-cargo**: added tracing spans and error detail to previously silent parse, registry-fetch, and filesystem paths (resolves #836) (#842)
- **deps-pypi**: `register_named_source`'s doc comment now notes it has no production caller and points to `register_chain` as the live path for named sources, closing staleness that previously misdirected a security fix (resolves #828) (#838)
- **deps-lsp**: fixed a `max_concurrent_fetches = 0` deadlock that could wedge fetches server-wide by starving the shared `fetch_permits` pool (resolves #833) (#841)
- **deps-maven, deps-gradle**: `generate_completions`' XML/DSL/catalog context dispatch is now a non-wildcard-matched enum instead of a `_ => vec![]` catch-all, preventing a new completion position from silently producing no completions; `deps-gradle`'s `fetch_license_from` also gained a `tracing::instrument` span (resolves #819, #823) (#831)
- **deps-cargo, deps-npm, deps-pypi, deps-go**: remaining registry log sites (alternate-registry-router tracing, Go's `compile_glob` malformed-`GOPRIVATE` warnings) now route through `RedactedUrl` instead of a raw string or `redact_userinfo` alone, closing a query-string-credential leak (resolves #824, #822) (#829)
- **deps-core, deps-maven, deps-nuget**: shared the bracket-interval version-range grammar via `deps_core::interval`, fixing `deps-nuget` silently accepting malformed ranges `deps-maven`/`deps-gradle` already rejected (resolves #821) (#830)
- **deps-core**: `redact_userinfo`'s unparseable-URL fallback now also redacts a colon-separated credential with no `@` (e.g. an npm `oauth2:`/GitLab CI job-token line) (resolves #810) (#814)
- **deps-core**: closed two further `redact_userinfo` gaps — a `?`/`#`/`/` inside a password no longer truncates the scan before it reaches the userinfo `@`, and the empty-authority `scheme:/path` fallback now also redacts a colon-separated credential with no `@` at all (resolves #826, #818) (#845)
- **deps-core**: `url_for_tracing`/`redact_userinfo` now redact a non-special-scheme `scheme:/path` credential (e.g. `c:/user:hunter2@evil`) that previously bypassed all redaction (resolves #811) (#827)
- **deps-core, deps-gitlab-ci, deps-lsp**: `IndexUrlError::InvalidUrl`'s payload is now a `RedactedUrl`, closing credential-log paths via a hostile `registries.gitlab_instance_host` value (resolves #808) (#809)
- **deps-core, deps-gitlab-ci, deps-cargo, deps-nuget**: fixed origin-pinning redirect policy to compare parsed URL origins/paths instead of raw string prefixes, closing a credential-leak bypass (#795)
- **deps-core** + all 14 ecosystem crates: a manifest's dependency count is now capped at 5000 per document, enforced at parse time via a shared `deps_core::DependencyBudget` (with the existing `dependency_cap` view-truncation kept as a backstop), closing an unbounded memory/outbound-registry-request amplification path from an adversarial manifest (resolves #796) (#802)
- **deps-core**: corrected a stale doc-comment reference to a nonexistent item in `in_use_version.rs` (resolves #773) (#779)
- **deps-core, deps-cargo, deps-npm, deps-pypi, deps-go, deps-nuget, deps-maven**: `DepsError`'s `Display`/`Debug` and several ecosystem-crate log lines no longer embed a workspace-declared registry URL's raw query string, closing a credential-exfiltration path (resolves #767) (#775)
- **deps-gradle**: version catalog/DSL completion no longer miscounts an escaped quote, via a generalized quote-parity helper in `deps-core` (resolves #738) (#771)
- **Breaking (pre-1.0, public API)**: **deps-core**: fixed 16 broken rustdoc intra-doc links invisible to the default CI rustdoc gate, renaming the public `in_use_version` function to `resolve_in_use_version`; also corrected the `Ecosystem` sealed-trait docs, which overclaimed compiler-enforced sealing rather than a documented contract (resolves #765, #770) (#772)
- **deps-core**: manifest parsing now runs on the blocking-thread pool instead of the calling tokio worker, and `LineOffsetTable::byte_offset_to_position` no longer rescans an ASCII line from its start on every call, fixing an O(n^2) slowdown on large single-line manifests (resolves #743, #742) (#747)
- **deps-pypi**: raw-text fallback completion no longer bare-inserts an unquoted package name into a `pyproject.toml` dependency array when no quote has been typed yet (resolves #737) (#741)
- **deps-lsp, deps-cargo**: raw-text fallback completion now rejects an unbounded prefix (>200 chars); `deps-cargo` raised `recursion_limit` to fix the nightly `-D warnings` fuzz-job build proving `Send` for a boxed future (same class as deps-nuget/deps-swift) (resolves #739) (#745)
- **workspace**: raised `recursion_limit` to 256 in every remaining crate, pre-empting the same fuzz-job `recursion_depth_exceeding_limit` failure already fixed for deps-cargo/deps-nuget/deps-swift instead of hitting it crate by crate (#768)
- **deps-pypi, deps-cargo, deps-core, deps-npm, deps-composer**: raw-text fallback completion no longer bare-inserts a package name after an already-closed TOML array value or duplicates an already-open JSON/quote key, via a shared escape-aware quote-parity check in `deps-core` (resolves #734, #733, #729) (#732)
- **deps-core** + all 9 lock-file providers: lock-file parsing now runs on the blocking-thread pool via a shared `read_and_parse_lockfile` helper, no longer stalling the LSP request worker (resolves #723) (#730)
- **deps-lsp**: NuGet/Maven raw-text fallback completion no longer inserts duplicate markup when the cursor is already inside an open attribute value or tag (resolves #724) (#728)
- **deps-core, deps-npm, deps-dart**: an unquoted, numeric-looking YAML scalar (e.g. a bare pnpm catalog range, or a two-component `version: 1.0` in `pubspec.lock`) is no longer misclassified as malformed, via a new shared `deps_core::yaml_scalar_string` helper (resolves #721) (#731)
- **deps-lsp**: NuGet raw-text fallback completion now actually fires inside `Include="..."`/`id="..."` on `PackageReference`/`PackageVersion`/`package` elements, instead of being permanently disabled (resolves #699) (#720)
- **deps-core, deps-maven, deps-gradle**: Maven `groupId`/`artifactId` -> URL-path construction is now a single shared `deps_core::maven_coordinate_path` helper, and `maven-metadata.xml` parsing now bounds retained version entries and bytes scanned instead of silently truncating (resolves #702, #698) (#715)
- **deps-nuget**: raised `recursion_limit` to fix the nightly `-D warnings` fuzz-job build, which failed proving `Send` for `unlisted_versions_for_hover`'s boxed future (same class of fix as deps-swift in #673) (#696)
- **deps-gradle**: license hover/policy no longer misses a license declared only on a Maven multi-module `<parent>` POM (e.g. Guava); the tier-3 license pre-fetch now has its own 10s timeout floor independent of a lower configured `fetch_timeout_secs` (resolves #692)
- **deps-core**: Gradle POM free-text license names are now normalized to SPDX at one shared `license_prefetch` read boundary instead of each consumer re-deriving its own branch (resolves #687)
- **deps-gradle**: Gradle POM license parsing now bounds total parse work by bytes read, in addition to capping retained entries and skipping oversized names, closing an unbounded-scan/allocation path (resolves #690) (#694)
- **deps-gitlab-ci, deps-maven, deps-core**: `GitlabInstanceHost`'s cached-host `RwLock` reads no longer panic on a poisoned lock; `find_date_time`'s date/time shape check no longer relies on an exactly-16-byte window; `byte_to_utf16_offset`/`text_range` no longer panic on a byte offset landing mid-character (`clippy::string_slice` now enforced on every crate root as a regression gate) (resolves #680) (#684) (#686)
- **deps-cargo**: sparse-index bearer token header value now zeroizes on drop instead of leaking a plaintext copy in an ordinary `String` (resolves #672) (#675)
- **deps-pypi**: a PEP 508 requirement with a malformed package name or extras entry no longer panics the parser (found via fuzzing, resolves #673)
- **deps-core, deps-deno**: a bare (operator-less) Deno `jsr:`/`npm:` or npm/Composer version requirement with no lock file present is now treated as an exact pin when it has the shape of a full version, instead of being misclassified as a Cargo-style implicit caret range (resolves #667, #664) (#668) (#666)
- **deps-core**: `net_policy.rs` doc comment no longer describes the DNS-rebinding gap as open — it is already closed by `BlockedAddrResolver` (resolves #655) (#656)
- **deps-core, deps-lsp**: hover/inlay-hint in-use-version and OSV vulnerability lookups now resolve each manifest occurrence against its own `version_requirement()` instead of a single collapsed lock-file value, so a renamed/aliased dependency pinned to a different major no longer mis-reports the other occurrence's version (resolves #649) (#653)
- **deps-cargo, deps-npm, deps-deno**: an explicit Cargo `package = "..."` rename and an npm `npm:<pkg>@<range>` alias now resolve hover/diagnostics/completion/OSV/lockfile lookups against the real package name instead of the local manifest alias, via a shared `deps_core::package::npm_style_name_boundary` helper (resolves #648, #654) (#657)
- **deps-core, deps-gradle, deps-cargo, deps-npm, deps-nuget, deps-lsp**: fixed flaky `fs_probe`-based tests under threaded (non-nextest) execution by serializing snapshot-diff tests with a shared guard (resolves #806) (#812)

### Changed
- **Breaking (pre-1.0, public API)**: converged registry-client method/type naming across `deps-core` and all 14 ecosystem crates — dropped `_typed` suffixes; renamed `get_versions_with_release_dates`->`get_versions_with`, `get_latest`->`get_latest_stable`, `get_gem_info`/`get_package_info`->`get_package_metadata`, `register_chain`/`register_routes`->`register_alternate`, `unlisted_versions_for_hover`->`unlisted_versions`, `get_latest_matching_for_manifest`/`select_latest_matching_for_manifest`->`get_latest_matching_with_context`/`select_latest_matching_with_context`; dropped the `get_` prefix from pure in-memory getters (`ResolvedPackages::version`/`all`, `EcosystemRegistry::for_filename`/`for_uri`/`for_lockfile`/`for_watched_config`); moved `ParseResult` from `types::` to `parser::`; deleted dead code (`get_gem_info`, `register_named_source`, `NpmVersionReq`) (#847)
- **deps-core**: new `impl_registry_versions_method!`/`impl_get_versions_with_passthrough!` macros replace ~24 hand-written, byte-identical `Registry` trait-impl wrappers; `registry_conformance!` gained a `ty:` form statically enforcing the canonical method names are true inherent methods, wired into 9/14 ecosystem crates; `ecosystem!`'s per-crate re-export lists now consistently include every `*Registry`/`*Formatter`/`*LockParser` type each crate defines (#847)
- **deps-core, deps-nuget, deps-pypi, workspace**: documented the deliberate pre-1.0 dependency-type couplings in public signatures (`reqwest::Error`, `yaml_rust2::Yaml`, `semver::VersionReq`), re-exporting `yaml_rust2`/`reqwest`/`package_url` from crate roots; gated `HttpCache`/NuGet bench-only helpers behind a new `test-util` feature, with CI passing the matching `--features` explicitly so `core_benchmarks`/`nuget_benchmarks` keep building (#847)
- **Breaking (pre-1.0, public API)**: **deps-cargo, deps-npm, deps-pypi, deps-go, deps-nuget, deps-maven**: migrated to `deps-core`'s `RedactedUrl` structural chokepoint — several crates' `InvalidEntry.raw`/`*UrlError::InvalidUrl` payloads are now `RedactedUrl` (was `String`), closing two previously-unredacted `Ok`-arm logs found during review; `deps-go`'s shared `IndexUrlError` migration deferred as a separate follow-up (resolves #801) (#807)
- **Breaking (pre-1.0, public API)**: **deps-core**: `DepsError::RegistryError.source` is now `SanitizedRegistryError` (was `reqwest::Error`); `RegistryError.package`/`HttpStatus.url`/`Offline.url`/`ResponseTooLarge.url` are now `RedactedUrl` (was `String`) (#789) (#800)
- **deps-core, deps-lsp, all 14 ecosystem crates**: `Ecosystem::id()` is now derived from a required, exhaustively-typed `ecosystem_id()` method instead of a runtime string parse; hand-written `Dependency`/`ParseResult` impls migrated to shared `impl_dependency!`/`impl_parse_result!` macros where byte-identical (resolves #791, #792) (#798)
- **deps-core, 12 ecosystem crates**: replaced the per-ecosystem, wildcard-matched `CompletionContext` dispatch in `generate_completions` with an exhaustive default in `deps-core` over three hooks; `deps-maven`/`deps-gradle` keep their own string-typed context for now (resolves #793) (#804)
- **deps-gradle, deps-core**: POM license scan's byte-budget guard now shares `deps-core::xml_bounds::exhausted_with` instead of a private lossy `as usize` cast, hardening the fail-closed conversion for 32-bit targets (resolves #725) (#771)
- **deps-lsp**: split the 11k-line `document/lifecycle.rs` god module into `lifecycle.rs`/`fetch.rs`/`osv_scan.rs`/`diff.rs`/`resolved.rs` by responsibility; pure move/re-export, no behavior change (resolves #754) (#764)
- **deps-core, deps-lsp, all 14 ecosystem crates**: raw-text fallback completion syntax and package-name completion insert-text are now two `Ecosystem` trait hooks (`fallback_completion_prefix`, `completion_insert_text`) each crate implements directly, replacing six non-exhaustive `EcosystemId` match tables previously centralized in `deps-lsp` (resolves #722) (#731)
- Consolidated the `indexing_slicing`/`unwrap_used`/`expect_used`/`string_slice` clippy restriction lints, previously duplicated as an identical attribute across all 16 workspace crates, into `[workspace.lints.clippy]`; removed the dead `non_std_lazy_statics` allow (resolves #689) (#693)
- **deps-core, deps-dart, deps-swift, deps-gradle, deps-deno**: license support (`fetch_license`, `license_source()`) is now a sealed `Ecosystem` trait method every crate implements, replacing four non-exhaustive `EcosystemId` predicates; the tier-3 license-fetch capability signal is folded into `LicenseSource` (`requires_dedicated_fetch()`), with a new `FetchedDeclaredSpdx` for Deno (resolves #688, #697) (#716)
- **deps-npm**: `package-lock.json` parsing now prefers a package entry's own `name` field over the lockfile-key-derived name, correctly naming `npm:` aliases (#657)
- **deps-core, deps-composer, deps-nuget, deps-cargo, deps-npm, deps-gradle**: extracted the duplicated lenient string-or-string-array JSON deserializer and the duplicated bounded ancestor-directory walk into shared `deps_core::json_helpers`/`fs_probe::config_ancestors` helpers (resolves #662, #757) (#665) (#763)
- **deps-core, deps-lsp**: documented NuGet's bare-version pin approximation and added a cross-ecosystem consistency test guarding `bare_requirement_policy` (resolves #669) (#674)
- **workspace**: removed 18 unused dependencies across 11 crates, moved 3 test-only dependencies to `[dev-dependencies]`, and added a `cargo machete` CI gate (resolves #670) (#675)
- **workspace**: `missing_docs` lint raised from `allow` to `warn`; added ~287 previously-missing `///`/`//!` doc comments across the workspace needed to make the flip clean (resolves #744) (#746)
- **workspace, CI**: split CI's `check` job into parallel `clippy`/`doc-and-hygiene` jobs, decoupled downstream jobs from the `fmt`+`check` gate, re-enabled per-target dependency caching for `cross-check`, switched `fuzz` to `Swatinem/rust-cache`, and added a `fuzz-tool` job building `cargo-fuzz` once for reuse across the matrix (resolves #750, #751, #752, #749, #748) (#762) (#761)
- **Breaking (pre-1.0, public API)**: **deps-cargo**: `ParseResult`/`ParsedDependency`/`DependencySection` renamed to `CargoParseResult`/`CargoDependency`/`CargoDependencySection`, matching the `<Ecosystem><Type>` prefix convention every other ecosystem crate follows (resolves #760) (#768)
- **workspace**: closed the #758/#759 lint-hygiene backlog — documented 29 missing `# Errors` sections (`missing_errors_doc` now `warn`), fixed the workspace's one `future_not_send` clippy hit, simplified 6 always-`Ok` PyPI parser helpers, justified/removed stray `#[allow(clippy::string_slice)]` sites, and added drift-resistant `EcosystemId` completeness/invariants tests replacing hand-written per-feature assertion lists (#776)
- **Breaking (pre-1.0, public API)**: **workspace, deps-lsp**: extended the `#[non_exhaustive]` API-stability pass to `deps-core`'s remaining public LSP/registry/version DTOs, every ecosystem crate's registry response/growth-prone-enum/`*ParseContext` types, and `deps-lsp`'s own config DTOs (`DepsConfig` and its 11 section structs, `WorkspaceRegistriesSetting`, `EcosystemRuntime`), reworking multi-arg `Foo::new` constructors into required-fields-only constructors with `with_*` setters (resolves #769, #778) (#777) (#780)
- **CI**: `cross-check`'s musl legs cache the custom `cross` Docker image needed for `aws-lc-sys`, avoiding a multi-minute `apt-get update` against a slow mirror on every run; the matrix also gained an `i686-unknown-linux-musl` leg for real 32-bit coverage (resolves #790) (#844) (#803)
- **workspace**: added `.gitleaks.toml` allowlisting `actions/cache` cache-key lines that `gitleaks`'s `generic-api-key` rule otherwise false-positives on (resolves #797) (#803)

### Dependencies
- Bump `dirs` from 6 to 7.0.0, plus transitive `Cargo.lock` refresh (#659)
- Bump `base64` from 0.22.1 to 0.23.1 (#658)

## [0.13.0] - 2026-09-05

### Added
- **deps-core, deps-github-actions, deps-gitlab-ci, deps-lsp**: bulk "Pin N {noun} to commit SHA" code lens generalized cross-ecosystem — GitLab CI `include:` entries now get the same batch quickfix GitHub Actions workflows already had (resolves #640) (#645)
- **deps-github-actions, deps-lsp**: bulk "Pin N actions to commit SHA" code lens for GitHub Actions workflows, applying every resolvable mutable-tag `uses:` pin in one edit via the existing per-step quickfix's `TagIndex` lookup (resolves #633) (#639)
- **deps-gitlab-ci**: mutable-ref SHA-pin diagnostic and "Pin to commit SHA" quickfix for `include: - project:`/`component:` entries (resolves #634)
- **deps-lsp**: `workspace/didChangeConfiguration` now re-parses and forces a full re-fetch for every open document affected by a live-reloaded setting that alters registry routing (`registries.workspace_registries`, `registries.nuget_user_profile_sources`, `registries.gitlab_instance_host`), bounded by a server-wide fetch-concurrency cap shared with cold-start loading (resolves #592) (#600)
- **deps-npm, deps-lsp**: watch `pnpm-workspace.yaml`/`.npmrc` for external changes and reparse already-open `package.json` documents so catalog/registry-resolved diagnostics stay current (resolves #590) (#595)
- **deps-npm**: pnpm workspace catalog (`pnpm-workspace.yaml` `catalog:`/`catalog:<name>`) resolution for `package.json` — hover/diagnostics/completion/inlay hints now treat a resolved catalog entry like a literal semver range, while an unresolved one (missing entry, unknown catalog, no workspace file, malformed YAML, duplicate default catalog) never gets silently rewritten by the "Update all outdated dependencies" quick-fix (resolves #587) (#589)
- **deps-gitlab-ci, deps-core, deps-lsp**: new GitLab CI/CD ecosystem — `include: - project:`+`ref:` and `include: - component:` CI/CD Catalog pins resolved against the GitLab repository-tags/project-releases APIs, self-hosted instances via `registries.gitlab_instance_host`, `GITLAB_TOKEN` support (resolves #466) (#596)
- **deps-nuget, deps-core, deps-lsp**: NuGet credentialed private feed authentication — a user-profile `NuGet.Config` `<packageSourceCredentials>` (`ClearTextPassword`, with `%ENV_VAR%` expansion) now attaches as a `Basic` `Authorization` header when it binds to a repo-declared source at the exact same URL, over a new origin-pinned, connect-address-guarded transport; a revoked credential's cached response is evicted on the next 401/403 (resolves #561) (#572)
- **deps-nuget, deps-core**: origin-pinned transport and registration-hive enrichment (publish-time freshness, hover-only unlisted marker) for workspace-declared/alternate NuGet feeds — closes spec 035's NFR-003(3) residual risk (resolves #562) (#572)
- **deps-lsp**: new `registries.nuget_user_profile_sources` setting (default `false`) opting a NuGet user-profile-only source (no repo `NuGet.Config` declaring it) into becoming an `AlternateRegistry` routing hop, trading away OSV/deps.dev/hover-trust for that feed's packages (#572)
- **deps-go, deps-core, deps-lsp**: `$GOENV` `GOPROXY`/`GOPRIVATE` support — a `GOPROXY` proxy chain (with `direct`/`off` sentinels) or a `GOPRIVATE`-matched module path now resolves to live hover/diagnostic/completion data from the configured private proxy (or fails closed with no data for `direct`/`off`) instead of always querying `proxy.golang.org`, failing closed on a bad hop rather than falling back to the public proxy (#558)
- **deps-nuget, deps-lsp**: NuGet private/custom feed support — in-repo `NuGet.Config` `<packageSources>`/`<clear/>`/`<disabledPackageSources>`/`<packageSourceCredentials>`/`<packageSourceMapping>` are now resolved to live hover/diagnostic/completion data instead of always querying `api.nuget.org`, failing closed on a bad/disabled/credentialed entry rather than falling back to the public feed (resolves #523) (#560)
- **deps-go**: `$GOENV` `GOPROXY`/`GOPRIVATE` follow-up hardening — test-injectable `$GOENV` path, oversized-`GOPRIVATE`-pattern warning, expanded edge-case/integration test coverage, and `GOPROXY` `,`/`|` separator docs (#563)

### Fixed
- **deps-gitlab-ci**: the mutable-ref-pin diagnostic's "no automated fix available" suffix is no longer shown for a `component:` `~latest`/partial pin when a "Pin to commit SHA" quickfix is actually available (resolves #643) (#645)
- **deps-lsp**: the diagnostics loading ceiling now scales with dependency count and `cache.max_concurrent_fetches` instead of a fixed multiplier, so a low concurrency setting on a larger manifest no longer forces premature `Failed` diagnostics (resolves #636) (#638)
- **deps-lsp**: diagnostics no longer stay stuck forever for a document that never leaves `LoadingState::Loading` (e.g. a background fetch task panic) — a fetch-timeout-derived ceiling now forces it to `Failed`, and a panicking background task is now supervised instead of silently discarding its result (resolves #632) (#635)
- **deps-gradle**: recognize modern/variant configuration names (`androidTestImplementation`, `debugImplementation`, `compileOnlyApi`, `kaptAndroidTest`, etc.) instead of a fixed literal whitelist (resolves #627) (#631)
- **deps-gradle**: fix mis-attributed name/version ranges for same-line dependencies sharing an identical coordinate or version (resolves #628) (#631)
- **deps-gradle**: fix `dependencies { }` block guard false-positiving on unrelated blocks like `dependenciesInfo { }` (resolves #629) (#631)
- **deps-gradle**: Kotlin DSL parser now shares a single capture-to-`GradleDependency` builder with Groovy DSL and recognizes the legacy `compile`/`testCompile`/`provided` configurations (resolves #625) (#626)
- **deps-composer**: a `require`/`require-dev` entry whose value isn't a string (e.g. an object) is now skipped instead of producing a dependency entry queried against Packagist (resolves #621) (#623)
- **deps-cargo, deps-npm, deps-nuget**: ancestor-walk depth cap now imports `deps-core`'s canonical `MAX_CONFIG_ANCESTOR_DEPTH` instead of each declaring its own duplicate copy (resolves #611) (#616)
- **deps-core**: `MtimeFileCache` enforces an 8 MiB size cap (checked via `fs::metadata`) before reading a config file's content, instead of always reading the full file before any safety guard runs (resolves #591) (#595)
- **deps-go**: oversized-`GOPRIVATE`-pattern warning now logs once per distinct `$GOENV` file content instead of once per LSP re-parse (resolves #565) (#567)
- **deps-go**: a `GOPROXY` separator preceding a dropped invalid hop is now merged onto the surviving transition with most-permissive-wins, instead of being silently discarded (resolves #564) (#567)
- **deps-go**: `has_goprivate()` now reflects whether a usable (compiled) `GOPRIVATE` matcher exists, instead of true whenever any raw pattern was declared — even a rejected one (resolves #566) (#567)
- **deps-go**: a malformed `GOPRIVATE` pattern (unterminated `[` character class) now logs a `tracing::warn!`, matching the existing oversized-pattern warning instead of silently never matching (resolves #568)
- **deps-go**: a `GOPRIVATE` character-class range with reversed bounds (e.g. `[c-a]`) now logs a `tracing::warn!` instead of silently compiling as an always-empty range with no observability, and `\`-escapes (`\]`, `\-`, `\\`) inside a character class now parse correctly instead of being misread as literal range bounds or terminating the class early (resolves #570)
- **deps-nuget**: a NuGet source that fails closed on credential binding now logs the source key, reason, and specific cause (debounced per config state, debug/warn severity matching the existing convention), instead of silently dropping the dependency with no observability (resolves #576) (#578)
- **deps-cargo, deps-pypi, deps-go, deps-nuget**: version completions now resolve the dependency under the cursor by position instead of by name, routing each occurrence through its own source (registry/alternate) via a shared `deps_core::completion::complete_versions_at_position` helper — fixes same-named dependencies with different sources silently offering no completions for either (resolves #593) (#598)
- **deps-core**: `MtimeFileCache` now bounds the read itself (`fs_probe::read_to_string_capped`) instead of relying solely on a preceding `fs::metadata` stat, closing a TOCTOU gap where a file swapped or grown between the stat and the read could bypass the 8 MiB size cap (resolves #597) (#601)
- **deps-npm**: version completions now resolve the dependency under the cursor by position instead of by name, matching deps-cargo/pypi/go/nuget's #598 migration and removing the now-dead name-based ambiguity handling — a consistency/parity fix, since npm's own per-manifest source resolution never actually produces same-named dependencies with different sources today (resolves #599) (#604)
- **deps-npm**: `find_dependency_positions` now scopes its search to each manifest section's own byte range instead of matching the first `"<name>":` occurrence anywhere in the file, fixing wrong/missing hover, completion, and diagnostic positions for a package name declared in multiple sections (e.g. `dependencies` and `devDependencies`) (resolves #605) (#609)
- **deps-composer, deps-core**: `find_positions` now scopes its search to each `require`/`require-dev` section's own byte range (via a new shared `deps_core::parser::find_json_section_byte_range`) instead of a single monotonically-advancing cursor across `serde_json::Map`'s alphabetical iteration order, fixing wrong/missing hover, completion, and diagnostic positions for a package name declared in both sections (same bug class as #605) (resolves #610) (#612)
- **deps-cargo**: an ancestor `Cargo.toml` found while walking up for workspace-root discovery is now read through `fs_probe::read_to_string_capped` (8 MiB cap) instead of an unbounded read with no size check at all (resolves #602) (#606)
- **deps-lsp**: cold-start document loading from disk now bounds the read itself (`fs_probe::read_to_string_capped`) and rejects non-regular files (e.g. a FIFO, which could otherwise hang the reading thread), instead of relying solely on a preceding `metadata` stat, closing the same TOCTOU gap #601 closed for `MtimeFileCache` (resolves #603) (#606)
- **deps-core**: `read_lockfile_content` now bounds the read via `fs_probe::read_to_string_capped` (new 32 MiB `MAX_LOCKFILE_BYTES` cap), off the tokio worker thread via `spawn_blocking`, instead of reading a discovered lock file with no size gate at all (resolves #607) (#615)
- **deps-core**: `locate_lockfile_for_manifest` now gates each candidate on `fs_probe::is_file` instead of `Path::exists`, so a non-regular file (FIFO, socket, directory) at a lock file's conventional name is no longer treated as found (resolves #607) (#615)
- **deps-gradle**: `load_gradle_properties`'s ancestor walk is now bounded by a 64-directory depth cap and each `gradle.properties` read via `fs_probe::read_to_string_capped` (8 MiB cap), instead of an unbounded walk to the filesystem root with an unbounded read (resolves #608) (#615)
- **deps-npm, deps-composer, deps-core**: dependency name/version positions are now read directly from a `jsonc-parser` AST (new `deps_core::json_ast` module) instead of substring-scanning manifest text, fixing a nested-object value that shares a dependency's name and a duplicate top-level section key (`require`/`require-dev`, `dependencies`/`devDependencies`) resolving to the wrong or a default `(0,0)` position — also widens hover/diagnostics/inlay-hints/code-actions to dependencies whose key needed a JSON escape, previously left without any position at all; also resolves the O(deps × section length) quadratic scan #609/#612 introduced (resolves #613, #614) (#617)
- **deps-deno**: `parse_deno_json` now checks the parsed AST's nesting depth against `deps_core::MAX_JSON_NESTING_DEPTH` (64), tightening `jsonc-parser`'s own existing internal recursion cap (512) for consistency with deps-npm/deps-composer's JSON depth guard — hardening, not a vulnerability fix, since `deno.json`/`deno.jsonc` parsing was already bounded (resolves #618) (#620)
- **deps-npm**: a `dependencies`/`devDependencies`/`peerDependencies`/`optionalDependencies` entry whose value is not a JSON string (e.g. an object) is now skipped instead of being queried against the registry and reported as an unknown package (resolves #619) (#622)

### Changed
- **deps-core, deps-npm, deps-composer**: `deps-npm` and `deps-composer` now share a single `deps_core::json_helpers::string_valued_entries` helper (and its test coverage) for skipping non-string dependency-map values, instead of each crate carrying its own duplicated guard and tests (resolves #624) (#630)
- **deps-lsp**: the #590 watched-config-file reparse path now also sends `workspace/diagnostic/refresh` (previously only inlay-hint/code-lens refresh), matching #592's config-change reparse — a deliberate improvement, not a side effect (resolves #592) (#600)
- **MSRV bumped to 1.98** — unlocks `assert_matches!` (replacing `assert!(matches!(...))` in tests) and `str::strip_circumfix` (replacing chained `strip_prefix`/`strip_suffix` in `deps-core`, `deps-gradle`, `deps-pypi`) (resolves #549) (#594)
- **deps-nuget**: `NuGetSourceChain.hops`/`NuGetRegistry::with_base` now carry per-hop credential/slot data (`ResolvedHop`) instead of a bare feed URL; `deps_lsp::register_ecosystems` now takes an `&EcosystemRuntime` instead of a bare `Arc<RegistryAccessPolicy>` — both breaking, pre-1.0, no alias (#572)
- **deps-core, deps-cargo, deps-nuget**: consolidated four independently hand-implemented "redact this secret from `Debug`/`Display`" wrapper types into a single `deps_core::secret::Redacted<T>` newtype (resolves #573) (#577)
- **deps-core, deps-cargo, deps-nuget**: renamed the secret-exposing `as_str()` accessor on `Redacted<T>` and its delegating wrapper types (`AuthToken`, `RedactedSecret`) to `expose_secret()`, so it can no longer be confused with an ordinary string conversion in a grep or code review (resolves #581) (#582)
- **deps-lsp, deps-nuget**: decomposed `handle_document_change` and `resolve_with_context` into named, independently-testable phase helpers — pure refactor, no behavior change (resolves #580) (#583)
- **deps-core, deps-pypi, deps-nuget, deps-go**: consolidated three independently hand-rolled "hash an ordered routing chain into an opaque identity key" implementations into a single `deps_core::hash_routing_key` helper; resulting chain-key digest values change (process-local cache keys only, never persisted or compared cross-process, so this is not observable); `deps_go::config::ChainSeparator` no longer derives `Hash` (breaking, pre-1.0, no alias) (resolves #579) (#584)
- **deps-core, deps-lsp**: decomposed `generate_hover` and `fetch_latest_versions_parallel`/`handle_document_open` into named, independently-testable helpers — pure refactor, no behavior change (resolves #586, #585) (#588)

### Removed
- **Breaking (pre-1.0, public API)**: **deps-core**: removed `find_json_section_byte_range` from `parser`'s public API, superseded by the AST-based `deps_core::json_ast` module (#613) (#617)

### Security
- **CI**: pin every third-party `uses:` action across `.github/workflows/*.yml` to a full commit SHA instead of a mutable tag, closing the tag-retargeting supply-chain exposure on this repository's own CI (resolves #641) (#644)
- **deps-core, deps-nuget**: credential material and its construction intermediates now zeroize on drop (resolves #574) (#577)

## [0.12.1] - 2026-09-03

### Added
- **deps-core, deps-lsp**: supply-chain trust signal in hover — OpenSSF Scorecard score and SLSA/attestation provenance status via deps.dev, for npm/Cargo/Go/Maven/PyPI/Bundler/NuGet, behind a new `supply_chain.enabled` toggle (resolves #543) (#554)

### Fixed
- **deps-core, deps-github-actions, deps-swift**: fixed sequential GitHub tag-pagination fetch exceeding the per-dependency timeout for high-tag-count repos (resolves #553) (#555)
- **deps-core, deps-lsp, deps-github-actions**: fixed false "Unknown package" diagnostic when a dependency's tags exist but none are full-semver-shaped (e.g. `dtolnay/rust-toolchain`), and a stray hover "Press Cmd+. to update version" footer with an empty "Recent versions" section in the same case (resolves #550) (#552)
- **deps-github-actions**: mutable-ref-pin diagnostic now fires for literal-named git tags (e.g. `taiki-e/install-action@cargo-deny`) previously misclassified as an undiagnosable branch pin (resolves #551) (#552)

## [0.12.0] - 2026-09-03

### Added
- **deps-github-actions, deps-core, deps-lsp**: new GitHub Actions ecosystem — hover, inlay hints, diagnostics, code actions, and code lens for `uses:` steps in `.github/workflows/*.yml`/`*.yaml`, covering tag, commit-SHA (optionally `# vX.Y.Z`-annotated), and branch pins via the GitHub tags API (resolves #208) (#471)
- **deps-nuget**: hover now flags an unlisted (delisted/pulled) NuGet version with a `*(unlisted)*` marker in "Recent versions", enriched from `RegistrationsBaseUrl/3.6.0` on the hover path only (resolves #451) (#458)
- **deps-nuget**: a multi-project `packages.<project>.lock.json` lock file is now resolved by the manifest's own project name instead of picking an arbitrary `packages.*.lock.json` match from the directory (resolves #451) (#458)
- **deps-pypi, deps-lsp**: `-r`/`-c` (and `--requirement`/`--constraint`) targets in a `requirements.txt`/`constraints.txt` file are now surfaced as clickable `documentLink`s, resolved relative to the containing file (resolves #452) (#458)
- **deps-core, deps-pypi**: the `requirements/*.txt` directory-layout convention (e.g. `requirements/base.txt`, `requirements/dev.txt`) is now recognized and routed to PyPI, matching a bare `requirements.txt` at the root (resolves #452) (#458)
- **deps-core, deps-cargo, deps-lsp**: Cargo custom/private registry support — a `registry = "<alias>"` or `registry-index = "<url>"` dependency resolved via `.cargo/config.toml`/`$CARGO_HOME/config.toml` now gets live hover/diagnostic/completion data from its own sparse index instead of no data at all; `$CARGO_HOME`-declared registries may attach a bearer token, workspace-declared ones never can (resolves #431) (#440)
- **deps-cargo, deps-lsp**: `[source.crates-io] replace-with` resolution to a sparse-index mirror — plain dependencies in a mirrored workspace now resolve against the mirror instead of crates.io, while still receiving crates.io-content-correct OSV scanning and hover links (resolves #441) (#447)
- **deps-core, deps-cargo, deps-lsp**: new `cargo.workspace_registries` setting (`off`/`public_only`/`all`, default `public_only`) blocking workspace-declared registry/source URLs that resolve to loopback, link-local, cloud-metadata, RFC1918/CGNAT/ULA, or internal-name hosts, plus redirect-hop host reclassification shared by every ecosystem — closes the SSRF/reachability-probing sign-off from #443 (#447)
- **deps-core, deps-npm, deps-composer, deps-lsp**: package-level deprecation/abandoned diagnostic and hover section (npm `deprecated`, Composer `abandoned`), plus a Composer-only "Replace with X" code action when a successor package is named (resolves #205) (#435)
- **deps-github-actions, deps-core, deps-lsp**: mutable-ref-pin security diagnostic for a `uses:` step pinned to a tag, with a "Pin to commit SHA" code action rewriting it to `{sha} # {tag}` via the existing tag/SHA index (resolves #473) (#477)
- **deps-core, deps-lsp**: `cache.enabled: false` now actually bypasses the HTTP entry-map cache instead of being silently ignored (resolves #482) (#491)
- **deps-core, deps-lsp, deps-maven**: new `network.offline` setting blocks every outbound registry/OSV/GitHub request, serving already-cached data where available (resolves #483) (#491)
- **deps-npm, deps-core, deps-lsp**: npm `.npmrc` custom/private registry support — project/user-tier `registry=`/`@scope:registry=` overrides now resolve to live hover/diagnostic/completion data instead of none, failing closed on a bad entry rather than falling back to `registry.npmjs.org` (resolves #502) (#510)
- **deps-pypi, deps-lsp**: PyPI private/custom index resolution — `requirements.txt` `--index-url`/`--extra-index-url`, Poetry `[[tool.poetry.source]]`, and uv `[tool.uv.index]`/`[tool.uv.sources]` now resolve to live hover/diagnostic/completion data instead of none, checking declared extras before the implicit `pypi.org` fallback and failing closed on a bad explicit entry rather than falling back to `pypi.org` (resolves #513) (#516)

### Changed
- **repo**: root `Cargo.toml` `[workspace.dependencies]` is now fully, case-insensitively sorted alphabetically (resolves #442) (#444)
- **repo**: per-crate `[dependencies]`/`[dev-dependencies]` tables in 8 member crates are now sorted alphabetically (resolves #445) (#446)
- **Breaking (pre-1.0, public API)**: `PackageVersions::yanked` field type changed from `Arc<[ConcreteVersion]>` to `Arc<[(ConcreteVersion, RemovalStatus)]>`, carrying each yanked/deprecated version's `RemovalStatus` (resolves #437) (#438)
- **deps-npm, deps-composer**: `AdvisoryDeprecated` no longer feeds the manifest-requirement yanked diagnostic; the #205 package-level deprecation diagnostic is now its sole signal (resolves #436) (#439)
- **Breaking (pre-1.0, public API)**: `deps-core` extracts a shared `Capped<T>` type for the "possibly-truncated list + total count" pattern, replacing the separate `Vec<T>` + `total_known: usize` fields on `DependencyVulnerabilities::advisories` and `UpgradeStatus::CandidateVulnerable::advisory_ids`; `DependencyVulnerabilities::fix_target_status` drops its redundant `Option` wrapper in favor of `UpgradeStatus::NotChecked` (resolves #469, #468) (#470)
- **deps-core, deps-swift, deps-github-actions**: extracted the duplicated GitHub tags-API client (owner/repo validation, auth-header setup, tags pagination, page parsing) into a shared `deps_core::github` module; no external behavior change (resolves #472) (#476)
- **Breaking (pre-1.0, public API)**: `deps-core`'s `GithubTagsClient::headers()` is now crate-private; authenticated GitHub requests go through the new `fetch_authenticated` method (trusted-origin-pinned), and the auth token is wrapped in a redacting `AuthToken` type that never leaks via `Debug`/`Display` (resolves #484) (#487)
- **Breaking (pre-1.0, public API)**: `deps-core`, `deps-lsp` consolidate the yanked/deprecation/fetch-failure maps into one `DependencyOutcome`/`DependencyOutcomes` type; `VersionData`'s three `with_yanked`/`with_deprecations`/`with_fetch_failed` builders and fields collapse into `with_outcomes`/`outcomes`, removing triplicated re-keying and pruning logic (resolves #481) (#488)
- **Breaking (pre-1.0, public API)**: `deps_core::lsp_helpers::generate_diagnostics_from_cache` gained a required `uri: &Uri` parameter, used to anchor `DiagnosticRelatedInformation` locations for collapsed fetch-failure diagnostics (resolves #479) (#489)
- **deps-core**: refactored `generate_diagnostics_from_cache`'s per-dependency checks into an explicit ordered rule pipeline; no behavior change (resolves #500) (#507)
- **deps-core**: order-sensitive diagnostics tests now pin exact `diagnostics[i]` message/code instead of presence-only checks, closing a regression-detection gap left by #500's refactor; no behavior change (resolves #508) (#509)
- **Breaking (pre-1.0, user-facing config)**: **deps-lsp**: `cargo.workspace_registries` is renamed to `registries.workspace_registries` (now also governs npm's `.npmrc` resolution); no compatibility alias, so a client still sending the old key falls back to defaults (resolves #502) (#510)
- **deps-gradle**: simplified regex caching from `OnceLock` + wrapper functions to `LazyLock<Regex>`, matching the `deps-swift`/`deps-bundler`/`deps-go` idiom; no behavior change (resolves #511) (#514)
- **Breaking (pre-1.0, public API)**: **deps-core**: split `EcosystemFormatter` into seven concern-scoped supertraits kept behind the same object-safe bound; downstream code can no longer `impl EcosystemFormatter for X` directly (implement the owning concern trait(s) instead), and calling a method through `&dyn EcosystemFormatter` now requires importing the specific trait that declares it (resolves #512) (#515)
- **Breaking (pre-1.0, public API)**: **deps-core, deps-cargo, deps-npm, deps-pypi**: deduplicated the three ecosystems' near-identical index-URL validation into a shared `deps_core::net_policy::validate_index_url`; `deps_cargo::config::RegistryIndexError` and `deps_pypi::config::PypiIndexUrlError` are now aliases of the new `deps_core::net_policy::IndexUrlError` (resolves #518) (#520)
- **deps-gradle**: added a dedicated unit test for the parens-no-version dependency pattern (`RE_NO_VERSION_WITH_PARENS`); no behavior change (resolves #517) (#524)
- **deps-core, deps-cargo, deps-npm**: extracted the near-identical mtime-gated config-file cache and counted filesystem probe from `deps-cargo`/`deps-npm` into a shared `deps_core::mtime_cache::MtimeFileCache`/`deps_core::fs_probe`; `deps-cargo`'s `.cargo/config.toml`/`$CARGO_HOME/config.toml` tiers now also probe `is_file()` before parsing (adopting `deps-npm`'s prior behavior), avoiding a blocking read from a FIFO/socket/device at that path; `ConfigFileCache`/`NpmConfigCache`'s `Debug` output is now just label/capacity/len instead of dumping the full cached-entry map (resolves #521) (#528)
- **deps-gradle**: Groovy DSL's eight dependency-pattern matchers consolidated into one shared extraction helper, fixing a latent dedup-bookkeeping gap that skipped `matched_positions` tracking in two of them (resolves #533) (#537)
- **deps-npm, deps-dart, deps-composer**: removed private duplicate `LineOffsetTable` structs, all three now use the shared `deps_core::lsp_helpers::LineOffsetTable`, matching the `deps-bundler`/`deps-go` dedup from #389 (resolves #542) (#545)
- **deps-github-actions**: `GithubActionsFormatter` now overrides `validate_package_name` for `owner/repo`-shape consistency with every other GitHub-identifier-shaped or coordinate-shaped ecosystem formatter (`deps-swift`, and the #402/#375 sweep); scoped to also accept the local-path (`./x`) and Docker-image (`docker://x`) `uses:` forms so those steps keep producing no diagnostic, unchanged from before (resolves #544) (#546)
- **deps-core**: `LineOffsetTable::byte_offset_to_position`'s manual char-boundary clamp loop replaced with `str::floor_char_boundary` (MSRV 1.91); no behavior change

### Fixed
- **deps-cargo, deps-core**: a `registry-index` value carrying literal userinfo credentials (e.g. `sparse+https://user:pass@host/`) that falls through to `.cargo/config.toml` alias resolution and still fails to resolve — or collides with another such value on the same `CARGO_REGISTRIES_*_INDEX` env-var name — no longer leaks the raw credential into either `tracing::warn!` log; `deps_core::net_policy::redact_userinfo` also now redacts a schemeless `user:pass@host` literal, which previously slipped through unredacted (resolves #536) (#540)
- **deps-composer**: an uppercase-`V`-prefixed version (e.g. `V3.1.0`) now correctly satisfies its declared requirement instead of always failing, matching the existing lowercase-`v` behavior (resolves #534) (#538)
- **deps-core, deps-npm**: replaced two intra-doc links (`fs_probe::snapshot`, `NpmRegistry::with_registry_base`) pointing at `test-util`-gated items with plain code spans, so `cargo doc` no longer fails `rustdoc::broken_intra_doc_links` when built without that feature (resolves #539) (#541)
- **deps-gradle**: a Groovy DSL dependency declaration with whitespace before the opening paren (e.g. `implementation ('junit:junit:4.13.2')`) is no longer silently dropped (resolves #525) (#527)
- **deps-gradle**: a Kotlin DSL dependency declaration with whitespace before the opening paren (e.g. `implementation ("junit:junit:4.13.2")`) is no longer silently dropped, matching the Groovy DSL fix (resolves #526) (#530)
- **deps-gradle**: `platform(...)`/`enforcedPlatform(...)`-wrapped BOM dependency coordinates (e.g. `implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.0"))`) are no longer silently dropped in Groovy and Kotlin DSL parsing (resolves #531) (#532)
- **deps-github-actions**: a tags-API page with one entry missing/malformed `commit.sha` no longer aborts the whole page's parse and silently truncates later pages — only that entry is now skipped (side effect of the #472 GitHub-tags-client extraction) (#476)
- **deps-core, deps-lsp**: the "requirement satisfiable only by a yanked version" diagnostic no longer lets a co-occurring package-level deprecation finding hide a genuine hard yank (resolves #437) (#438)
- **deps-deno, deps-npm**: an exact-pin `npm:` dependency in `deno.json` no longer surfaces the yanked-worded diagnostic, matching the equivalent `package.json` dependency's post-#436 behavior; `jsr:` specifiers are unaffected (resolves #448) (#456)
- **deps-core**: block DNS-rebinding to loopback/link-local/cloud-metadata/unspecified addresses at connect time, shared by every ecosystem crate (resolves #449; RFC1918/CGNAT residual tracked in #455) (#457)
- **deps-deno**: a `jsr:` range requirement satisfiable only by yanked versions now surfaces the yanked diagnostic, matching Cargo/PyPI/Dart's behavior for the equivalent case (resolves #454)
- **deps-lsp**: fetch-failure toast no longer implies every counted package produced a "Registry lookup failed" diagnostic, since the count also includes not-found lookups, which surface as "Unknown package" instead (resolves #490) (#497)
- **deps-core, deps-cargo, deps-lsp**: `cargo.workspace_registries`' `public_only`/`off` now enforced at connect time (resolved address) and on every redirect hop, not just the declared URL string at parse time, closing a DNS-rebinding bypass to RFC1918/CGNAT-range hosts (resolves #455) (#460)
- **deps-core, deps-lsp**: the OSV vulnerability-fix code action's recommended target version is now independently verified against OSV before being offered, instead of only ever checking the registry's "latest" version (resolves #462) (#467)
- **deps-github-actions, deps-core**: hover no longer renders a dead empty-URL link or a misleading "Press Cmd+. to update version" footer for a non-resolvable `uses:` ref (local composite action, Docker image) (resolves #474) (#475)
- **deps-core, deps-github-actions, deps-lsp**: a rate-limited GitHub Actions registry lookup now surfaces its actionable hint (e.g. "set GITHUB_TOKEN") in the "Registry lookup failed" diagnostic instead of the generic fallback (resolves #478) (#485)
- **deps-lsp**: the one-shot "failed to fetch" toast no longer reports a not-found race winner over a co-occurring actionable failure (e.g. rate limit) in the same batch, and now always states the affected package count (resolves #480) (#489)
- **deps-core, deps-github-actions**: a tripped rate-limit gate no longer fans out one near-duplicate diagnostic per remaining dependency; fetch failures now collapse into a single diagnostic per manifest, naming every affected dependency via related information and still surfacing a shared actionable hint when one applies (resolves #479) (#489)
- **deps-github-actions, deps-core**: hover release-age hint and cooldown diagnostic now fire for GitHub Actions — `GithubActionsRegistry` enriches tags-API versions with GitHub Release publish dates via a new shared `deps_core::github::ReleaseDatesCache`, also adopted by `deps-swift` (resolves #486) (#494)
- **deps-lsp**: a client that never answers a server-initiated `workspace/inlayHint/refresh`, `workspace/codeLens/refresh`, `client/registerCapability`, or `workspace/diagnostic/refresh` request no longer permanently stalls the OSV vulnerability commit and diagnostics publish for that document; these requests are now capability-gated and timeout-bounded (5s) instead of awaited unconditionally on the critical path (resolves #493) (#495)
- **deps-lsp**: a client that never answers `workspace/applyEdit` for `deps-lsp.updateVersion` or `deps-lsp.updateAllOutdated` no longer permanently occupies a `workspace/executeCommand` concurrency slot; the request is now timeout-bounded (5s), same as #493's fix (resolves #496) (#498)
- **deps-lsp**: `cold_start.rate_limit_ms` now actually rate-limits cold starts instead of being parsed and silently ignored in favor of a hardcoded 100ms interval (resolves #499) (#504)
- **deps-github-actions**: resolve SHA-pin quickfix never firing for bare-major moving GitHub Actions tags (v3, v4) (resolves #503) (#505)
- **deps-core, deps-npm, deps-pypi, deps-cargo**: a literal userinfo credential in a registry/index config value (e.g. `.npmrc` `registry=https://user:pass@host/`) no longer leaks into `tracing::warn!` logs or `InvalidEntry`/error-surfaced text on validation failure, including when the value also fails to parse as a URL (resolves #522) (#529)
- **deps-core, deps-github-actions**: hover no longer shows the "Press Cmd+. to update version" footer for a dependency with no actual data or code action while `network.offline` is set (resolves #501) (#506)

### Removed
- **Breaking (pre-1.0, public API)**: **deps-lsp**: dropped the dead `CacheConfig::refresh_interval_secs` field — `HttpCache` has no local TTL concept to attach it to (resolves #492) (#498)

## [0.11.1] - 2026-09-01

### Fixed
- **deps-pypi, deps-core, deps-lsp**: PyPI package-name completion, previously a permanent zero-results stub, now serves matches from a live PyPI package-name index (resolves #419) (#426)
- **docs**: `ECOSYSTEM_GUIDE.md`'s Deno row now lists code lens support, matching the shared `deps-core` default it already receives (resolves #410) (#416)
- **.gitignore**: added globs for common secret files (SSH private keys, `*.key`/`*.pem`/`*.p12`/`*.pfx`/`*.jks`/`*.keystore`, `*.credentials`, `credentials.json`, `secrets/`) to prevent accidental commits (resolves #411) (#412)
- **deps-lsp**: background cold-start rate-limiter cleanup task no longer discards its `JoinHandle`, so a panic surfaces as an `error!` log instead of silently stopping cleanup forever (resolves #408) (#413)
- **deps-go, deps-bundler, deps-dart, deps-composer, deps-nuget, deps-swift**: structurally invalid package names/module paths now report "Invalid package name" instead of a misleading "Registry lookup failed" diagnostic (resolves #402) (#406)
- **docs**: `ECOSYSTEM_GUIDE.md` and the ecosystem-crate template now teach the current direct-`DepsError`-construction convention instead of the per-crate error wrapper pattern removed in #398 (resolves #403) (#405)
- **deps-core, deps-lsp**: duplicate dependency names within a manifest (e.g. the same crate under `[dependencies]`/`[dev-dependencies]` or multiple `[target.*.dependencies]` blocks) no longer collapse via name-only `HashMap` in the diff/yanked-probe/OSV-scan pipeline, so an edit to any occurrence is correctly diffed and neither yanked nor OSV findings leak between occurrences pinned to different versions (resolves #394)
- **deps-cargo**: dependencies declared under `[target.<cfg-expr-or-triple>.dependencies|dev-dependencies|build-dependencies]` are now parsed and visible to hover/diagnostics/completion, same as top-level ones (#396)
- **deps-cargo**: a git dependency's `tag`/`branch`/`rev` key is no longer dropped, populating `DependencySource::Git.rev` (#396)
- **deps-cargo**: invalid file URI during workspace-root discovery now reports `DepsError::InvalidUri`, matching every other ecosystem, instead of the previously divergent `DepsError::CacheError` (#398)
- **deps-pypi, deps-lsp**: package-name completion now works for PEP 621 `dependencies`/`optional-dependencies` arrays in `pyproject.toml`, which previously always returned zero results (resolves #390) (#397)
- **workspace**: bumped the transitively-pinned `chacha20` from the yanked `0.10.1` to `0.10.2` in `Cargo.lock`, reachable via `reqwest`'s optional HTTP/3 stack (resolves #407) (#414)
- **deps-dart, deps-composer**: `compare_versions` no longer truncates prerelease/qualifier suffixes, so a prerelease no longer compares equal to its stable counterpart (resolves #418) (#420)
- **deps-composer**: "latest version" selection now excludes alpha/beta/RC releases by default, matching Composer's `minimum-stability: stable` semantics, unless the requirement itself names an unstable version; a wildcard requirement still resolves a prerelease-only package instead of reporting no version found (resolves #421) (#422)
- **deps-swift**: a package whose only tags so far are prerelease now resolves under a wildcard requirement instead of `select_latest_matching` returning `None` (found via #421's cross-ecosystem conformance test) (#422)
- **deps-nuget**: a package whose only versions are prerelease now resolves under an existence-check wildcard requirement (`*`/empty) instead of `pick_latest_matching`/`select_latest_matching` returning `None` (resolves #423) (#425)
- **deps-composer, deps-core, deps-lsp**: "latest version" selection now honors `composer.json`'s `minimum-stability` field and per-dependency `@stability` flags (e.g. `^1.0@beta`), and consistently classifies separator-less/dot-separated prerelease suffixes (`1.0.0RC1`, `2.6.3.alpha`) regardless of `v`-prefix (resolves #424) (#428)
- **deps-core, deps-lsp, all 12 ecosystem crates**: `Ecosystem::generate_completions` now reports LSP `isIncomplete` per call (`Completions { items, is_incomplete }`) instead of a static per-ecosystem flag, so only PyPI's package-name search is flagged incomplete — not every completion request (version, comment, `[build-system]`, ...) in a Python manifest (resolves #427) (#429)

### Changed
- **Breaking (pre-1.0, internal API)**: `ConcreteVersion` newtype introduced and threaded through `Version`/`Metadata`, `EcosystemFormatter`, `RequirementMatcher`, `PackageVersions`/`VersionData`, and `deps-lsp`'s `DocumentState`/lifecycle fetch path, replacing bare `&str`/`String` for a resolved registry version — mirrors the `PackageName`/`VersionReq` newtypes from #191/#209 (resolves #214) (#434)
- **deps-core and all ecosystem crates**: untrusted JSON (registry responses, manifests, lockfiles) is now depth-guarded to 64 levels before `serde_json` deserialization, for consistency with the existing TOML/YAML manifest guards and an earlier, cheaper rejection than `serde_json`'s own built-in 128-level recursion limit — not a fix for a crash, which `serde_json` already prevented (resolves #430) (#432)
- **deps-bundler, deps-go**: removed private duplicate `LineOffsetTable` structs, both now use the shared `deps_core::lsp_helpers::LineOffsetTable` (resolves #389) (#395)
- **deps-cargo, deps-npm, deps-composer, deps-dart, deps-deno, deps-go, deps-gradle, deps-maven, deps-nuget**: removed per-crate `{Ecosystem}Error` wrapper enums; call sites now construct `deps_core::DepsError` directly (resolves #388) (#398)
- **deps-core, deps-go**: documented that `deps-go`'s module-path validation intentionally shares `DepsError::InvalidVersionReq` with version-string rejections, no new variant added (resolves #399) (#401)
- **deps-core**: resolved 5 open CodeQL code-scanning alerts (`rust/non-https-url`, `rust/cleartext-logging`) in `cache.rs` test code, none reachable from production paths (#409)
- **ci**: `cargo deny check advisories` now fails on a yanked crate (`yanked = "deny"`) instead of only warning (resolves #415)

## [0.11.0] - 2026-08-24

### Added
- **deps-core, deps-lsp**: diagnostic for an unsatisfiable version requirement (no published version matches), with configurable severity, across all 11 ecosystems (resolves #206) (#256)
- **deps-core, deps-lsp**: quick-fix code action rewriting an unsatisfiable requirement to the cached latest version (resolves #250) (#304)
- **deps-lsp**: `textDocument/codeLens` "Update N outdated dependencies" command applying a batch `WorkspaceEdit` (resolves #170) (#202)
- **deps-core**: vulnerability-aware diagnostics via the OSV.dev batch API, with a hover "Security advisories" section, across all 11 ecosystems (#215)
- **deps-core**: vulnerability-aware code action to update to a fixed version, filterable via `CodeActionParams.context.only` (resolves #216) (#236)
- **deps-core, deps-lsp**: release-freshness signal — publish age on hover/completion and a cooldown callout on outdated diagnostics — across all 11 ecosystems, with live config reload; several ecosystem `Version` types gain `published_at: Option<PublishTime>` (**Breaking, pre-1.0, public API**) (#145/#219, #220/#222/#294, #221/#225/#277, #293, #316)
- **deps-pypi**: `requirements.txt`/`constraints.txt` manifest support, reusing the shared PEP 508 parser (resolves #203) (#234)
- **deps-deno**: new Deno/JSR ecosystem — `deno.json`/`deno.jsonc`, `jsr:`/`npm:` specifier dispatch (resolves #207) (#309)
- **deps-core**: `validate_package_name` hook for ecosystem-specific name linting ("Invalid package name" vs "Unknown package"), implemented for npm (resolves #192)
- **deps-core**: shared `normalize_operator_spacing` helper replacing duplicated deps-dart/deps-composer copies (resolves #272) (#328)
- **deps-core**: `HttpCache` enforces a byte budget (`MAX_CACHE_BYTES`, 64 MiB) alongside the existing entry-count limit, with a per-entry admission cap, and fixed an inverted eviction-order bug so both limits now evict oldest-first (resolves #142)
- **workspace**: `clippy.toml` lints the DashMap Ref-across-await hazard project-wide via `await-holding-invalid-types` (#334) (#354)
- **deps-core**: shared `assert_dot_segment_gated_or_contained` regression-test helper guarding the dot-segment/unvalidated-URL-sink defect class, wired into 11 of 12 ecosystem crates (resolves #365)
- **deps-core, deps-cargo, deps-npm, deps-swift**: unsatisfiable-requirement warning now names a matching prerelease when one exists (resolves #299) (#305)
- **deps-core**: extracted reusable `has_default_prerelease_marker` from `Version::is_prerelease()`'s default heuristic (resolves #327) (#330)
- **Breaking (pre-1.0, public API)**: `Version::is_yanked() -> bool` replaced by `Version::removal_status() -> RemovalStatus` (`Available`/`AdvisoryDeprecated`/`Yanked`) (resolves #348) (#363)

### Fixed
- **docs**: documented each editor's own toggle for inlay hints, code lens, and inline diagnostics (all off by default in Zed and Neovim, code lens unsupported in Helix), since `deps-lsp`'s `initialization_options` alone don't make these features visible
- **deps-maven, deps-cargo, deps-gradle**: `MavenFormatter`/`CargoFormatter`/`GradleFormatter` now override `validate_package_name`, surfacing "Invalid package name" instead of "Unknown package" for a structurally invalid coordinate/name (resolves #369, #382, #375) (#374, #387)
- **deps-cargo, deps-go, deps-nuget, deps-composer, deps-swift, deps-deno, deps-core**: closed remaining gaps in the dot-segment/unvalidated-URL-sink regression sweep — non-ASCII/empty-name panics, missing per-character name encoding, unvalidated `.`/`..` identifiers reaching a registry-fetch URL builder, and silent (non-warning) rejection paths across package/version/URL builders (resolves #357, #361, #371, #376, #377, #378, #379, #380) (#374, #384, #386)
- **deps-core**: closed the DashMap `Ref`-held-across-await family of liveness hazards across hover/completion/code_actions, inlay hints, config reload, and `LockFileCache` (resolves #317, #319, #333, #334, #350) (#318, #325, #354, #358)
- **deps-core**: hover falls back to `Registry::get_latest_matching` for the **Latest** line on a Go module whose entire version list is pre-release/pseudo-versions (resolves #373) (#383)
- **deps-maven**: hover no longer renders a broken "package not found" section for a `groupId`/`artifactId` rejected by the dot-segment guard (resolves #366) (#368)
- **deps-core**: `LockFileCache::get_or_parse` now stats the lock file's mtime before parsing, closing a TOCTOU window where a concurrent rewrite could cache stale content under a fresh mtime (resolves #359, #360) (#362)
- **deps-core, deps-swift**: code actions and the "update all" lens never fired for a Swift dependency due to a literal-span guard mismatch; new `Dependency::version_literal()` (resolves #367)
- **deps-swift**: `validate_owner_repo` now rejects a `.`/`..` owner or repo segment (resolves #357)
- **deps-composer, deps-core**: an abandoned Packagist package's installable versions are no longer excluded from resolution, and hover's Latest/(latest) marker now resolves through the same `select_latest_matching` pick as the diagnostics cache (resolves #347, #348) (#363)
- **deps-npm, deps-deno, deps-cargo, deps-pypi, deps-dart, deps-maven, deps-gradle, deps-lsp**: packages whose every published version is deprecated/yanked/prerelease no longer misreport as "Unknown package"; the release-cooldown message now fires for npm/Deno/Maven/NuGet/Swift; Maven/Gradle diagnostics no longer recommend a prerelease as latest (resolves #338, #339, #340, #364) (#352)
- **deps-bundler, deps-core**: hover's "Recent versions" list no longer repeats a version per RubyGems platform, and its `(latest)` marker now matches the stable-version pick instead of the raw highest entry (resolves #311, #313) (#321)
- **deps-core, deps-pypi, deps-cargo, deps-dart, deps-swift, deps-npm, deps-deno**: `Version::is_prerelease()`'s default hyphen-substring heuristic missed non-hyphenated prerelease conventions across 6 ecosystems relying on it unmodified (resolves #322)
- **deps-bundler**: overhauled version comparison and requirement matching to match RubyGems' actual `Gem::Version`/`Gem::Requirement` semantics — tokenized `compare_versions`, a fuzz-verified port of `<=>`/`canonical_segments`, pessimistic (`~>`) matching ported from `#bump`, short `-a`/`-b` stability aliases, padding-stripping regex parity, requirement-operand validation before matching, and canonical equality for `=`/`!=`/bare pins (resolves #322, #323, #327, #331, #332, #345) (#330, #353); **Breaking (pre-1.0, public API)**: `SwiftVersion` gained a `prerelease: bool` field as part of the same #327 fix
- **deps-bundler**: exact-pin unsatisfiable-requirement suppression narrowed to a max-only range check instead of suppressing every exact pin (resolves #252) (#297)
- **deps-lsp**: `RegistryProgress::start` no longer sends `window/workDoneProgress/create` to a client that never advertised support, an LSP 3.17 violation; the read-response hang-detection timeout gained direct unit test coverage (resolves #290, #291) (#296)
- **deps-bundler**: fixed the yanked-diagnostic path incorrectly trusting RubyGems' always-empty yank signal (resolves #298) (#301)
- **deps-lsp, deps-core, deps-maven, deps-swift**: fixed a family of UTF-16-code-unit-vs-byte-offset and byte-vs-char-count bugs in completion prefix handling, causing panics or wrong completion behavior on multi-byte input (resolves #244, #258, #265)
- **deps-maven**: `get_versions` now orders by `maven-metadata.xml`'s `<release>`-designated entry (falling back to the first non-prerelease entry) instead of pure version sort, and a malformed `maven-metadata.xml` now surfaces as an error instead of silently truncating the version list
- **deps-swift**: `SwiftRegistry::get_versions` now paginates up to 30 pages (3000 tags) instead of stopping at page 1, and recognizes uppercase-`V`-prefixed tags, fixing silently omitted releases on large repositories (#273)
- **deps-core, deps-lsp**: threaded configured diagnostic severities into the live "Unknown package"/"Newer version available" diagnostics, wired a new "requirement satisfiable only by a yanked version" diagnostic and an in-use-version-yanked diagnostic into the live cache path, and reconciled the two so a dependency gets exactly one yanked diagnostic (resolves #224, #233, #247, #263)
- **deps-pypi**: dotted package names declared as Poetry table keys (e.g. `"zope.interface"`) now correctly match their lock file entries via a canonical PEP 503 normalizer (resolves #212)
- **deps-core, deps-pypi**: `generate_code_actions`'s "update version" action no longer writes a `TextEdit` for a `version_range` that no longer slices to its declared requirement text, and PyPI's `start_offset` computation now scans raw source text instead of the normalized/rejoined name (#231)
- **deps-core**: the plain "update to `<version>`" REFACTOR action loop now skips a display item whose formatted edit text already matches the declared requirement (resolves #238)
- **deps-maven, deps-gradle**: `version_satisfies_requirement` now parses bracket-interval range syntax and comma unions instead of plain string equality (resolves #172)
- **deps-maven**: `search_typed` (Maven/Gradle completion) is more resilient to `search.maven.org`'s intermittent silent hangs via retry, budget-aware timeout, and stale-cache fallback (partially mitigates #274)
- **deps-lsp, deps-maven**: fixed a Maven/Gradle completion query mismatch between primary and fallback search paths, and closed two residual `search_typed` reliability gaps (#282, #292)
- **deps-gradle**: an unresolved `$var`/`${var}` version reference is now treated as satisfied instead of producing a spurious outdated diagnostic (resolves #183)
- **deps-core**: added a tri-state `RequirementStatus` (`UpToDate`/`Outdated`/`Unresolved`) so inlay hints skip an unresolved requirement instead of rendering a false "up to date" badge (resolves #189)
- **deps-gradle**: a version-catalog dependency whose `version.ref` alias is missing or empty is now treated as unresolved instead of always comparing as outdated (resolves #190)
- **deps-maven**: range/interval bound matching now normalizes a missing trailing version segment as equal to zero, matching Maven's own comparison rule (resolves #182)
- **deps-gradle**: `version_satisfies_requirement` no longer panics on a single-character range requirement (resolves #187)
- **deps-lsp**: `didOpen`/`didChange` content is now bound to the same 10MB limit already applied to disk-loaded documents, with client-visible rejection notices (resolves #161)
- **deps-lsp, deps-maven**: Maven completion no longer inserts a malformed dependency block missing `<groupId>` (resolves #210)
- **deps-lsp, deps-swift**: Swift completion no longer inserts an invalid `Package.swift` URL/`from:` clause (resolves #211)
- **deps-maven**: fixed a UTF-16/byte-offset panic in `detect_xml_context` on multi-byte characters, widened its replace range to cover the whole existing tag value instead of just the typed prefix, and removed a dangling `v`/`"Latest: "` suffix when a search result has no version (resolves #217, #218)
- **deps-lsp**: `server_capabilities()` now advertises `CodeActionKind::QUICKFIX` alongside `REFACTOR`, so clients can actually request the vulnerability-fix action
- **deps-go, deps-lsp**: the OSV scan now uses `go.mod`'s declared version instead of stale `go.sum`-derived `resolved_versions`, fixing false-negative "Clean" results; a new `osv_version` hook strips the `v` prefix before querying OSV (resolves #228)
- **deps-core, deps-go, deps-lsp**: the same `go.sum` staleness also reached hover, diagnostics, and inlay hints beyond the OSV-scan path; a new `manifest_requirement_is_resolved_version` hook prefers `go.mod`'s declared version there too (resolves #235)
- **deps-gradle, deps-core**: preserved Gradle's `!!` strict-version marker through the "update version" code action and the "update all" lens, and fixed strict-marker comparison so a satisfied strict pin no longer shows a permanent false "Newer version available" (resolves #268)
- **deps-core**: package-name completion's `textEdit.range` is no longer hardcoded to `(0,0)-(0,0)` for the shared completion path or Gradle's catalog/DSL completion (resolves #232)
- **deps-npm**: `find_dependency_positions` no longer panics on a multi-byte UTF-8 character straddling its raw-byte search-window offset (resolves #230)
- **deps-composer**: `find_positions` had the same raw-byte-offset panic as the deps-npm bug above; fixed identically (resolves #245)
- **deps-core**: added `rt-multi-thread` to the crate's own `tokio` dev-dependency so an isolated `-p deps-core` build compiles its bench target (resolves #241)
- **deps-core**: the plain "update to `<version>`" REFACTOR loop could still emit two byte-identical actions in two more cases beyond #238; deduplicated via one running `HashSet` of formatted edit text (resolves #242)
- **deps-maven, deps-gradle, deps-nuget**: `compile_requirement` now parses a requirement's range/pattern once per dependency instead of re-parsing on every candidate version scanned (resolves #249)
- **deps-core, deps-cargo, deps-bundler**: `DependencySource::CustomRegistry` is no longer classified as resolvable against the public registry, preventing misleading version checks against an unrelated public package of the same name (resolves #248)
- **deps-swift**: `SwiftRegistry::get_versions`'s pagination loop now logs a warning when it stops at its page cap while the last page was still full, instead of truncating silently (resolves #253)
- **deps-dart, deps-composer, deps-gradle, deps-pypi, deps-maven, deps-nuget**: fixed six ecosystem-specific edge cases in the unsatisfiable-requirement diagnostic's `compile_requirement` predicate — spaced range operators, Gradle `!!` shorthand, PEP 440 local versions, timestamped Maven `-SNAPSHOT` variants, and empty NuGet version attributes (resolves #251)
- **deps-core, deps-lsp**: a registry fetch error or timeout is no longer indistinguishable from a genuinely nonexistent package; now reports "Registry lookup failed" instead of a misleading "Unknown package" (resolves #267)
- **deps-lsp** (test infrastructure): fixed flaky/hanging integration tests — bounded notification-wait retry, a real read-response timeout, corrected `$/progress`/`workDoneProgress` request handling in the test harness, and wired the nextest `--profile ci`/`--profile coverage` flags CI was silently not using (resolves #275, #285, #286, #287)
- **deps-core, CI**: documented `test-util`'s TLS-relaxation side effect and added a CI dependency-tree check preventing the feature from leaking into a release build (resolves #278, #279)
- **deps-deno**: complete partial `jsr:`/`npm:` specifier prefixes instead of showing no suggestions; share one `NpmRegistry` instance with npm to avoid duplicate packument fetches; removed a stale "completion dead zone" limitation note from README (resolves #335) (#310, #312, #324, #346)

### Security
- **deps-core, deps-nuget**: `HttpCache` now enforces a redirect policy — blocks `https`->`http` downgrades, and blocks cross-origin redirect escapes for NuGet's registration-hive fetches (#300)
- **Breaking (pre-1.0, public API)**: **deps-pypi**: bounded PEP 508 requirement length (`MAX_REQUIREMENT_LEN`, 4 KiB) to close an O(n²) DoS in `pep508_rs`'s extras-list parsing, surfaced as a new `PypiError::RequirementTooLong` variant on a now-`#[non_exhaustive]` `PypiError` (resolves #229)
- **deps-core**: validated and length-capped OSV advisory `fixed`-version and advisory-id strings before they reach a manifest `TextEdit`, closing a manifest-breakout injection vector from a malformed upstream advisory record
- **deps-core** and 10 ecosystem crates: closed the version/package-name/URL sanitization sweep — a shared allowlist gate (`is_safe_version_string`) in front of every version-derived `TextEdit`/completion path; dot-segment/unsafe-name rejection before registry-fetch and completion-`TextEdit` URLs are built across Maven, Swift, Bundler, Dart, npm, Deno, Cargo, PyPI, Composer, Go, Gradle, and NuGet; a no-op guard against emitting an edit for an empty/whitespace latest version; and warn-level logging on every rejection (**Breaking, pre-1.0, public API**: the primary Maven/Swift completion path now returns `Option<CompletionItem>`) (resolves #302, #303, #314, #336, #337, #341, #344, #349, #351) (#320, #342, #346, #355, #356)

### Changed
- **Breaking (pre-1.0, internal API)**: `PackageName`/`VersionReq` newtypes introduced and threaded through `Dependency`, `Registry`, `EcosystemFormatter`, and every package-name-keyed cache, replacing bare `&str`/`String` (#119/#121, #191, #193, #194, #200, #201, #209)
- **Breaking (pre-1.0, internal API)**: `generate_hover`/`generate_diagnostics`/`generate_completions` gained `FreshnessSettings` and `DiagnosticSeverities` parameters, threaded through every call site (#145/#219, #224)
- **deps-maven, deps-gradle**: unified single-interval range parsing into `deps_maven::interval` (resolves #184)
- **deps-lsp**: `DocumentState::ecosystem_id` is now a method instead of a stored field, removing a desync risk (resolves #155)
- Converted several `async fn` with no `.await` to plain `fn -> impl Future`, satisfying clippy's `unused_async_trait_impl` lint; no behavior change
- **deps-pypi**: canonical package-name normalization is now PEP 503 everywhere; the legacy `-`->`_` lock file key space is deleted (**Breaking, pre-1.0, no compat shim**)
- **deps-core**: `Ecosystem::generate_code_actions` gained a `content: &str` parameter, needed for the literal-span edit guard
- **deps-core**: consolidated five per-ecosystem `compile_requirement -> None` guards into one `compile_requirement_unless` helper; pure refactor, no behavior change (resolves #254)
- **CI**: `cross-check` no longer depends on the `check` job, shortening the critical path (#262)
- **deps-core**: extracted a shared `single_file_edit` helper for quickfix/refactor code actions, and split the ~11,000-line `lsp_helpers.rs` into feature modules; pure refactors, no behavior change (#329)

### Removed
- Removed unused `async-trait` workspace dependency from root `Cargo.toml` and 10 crate manifests (#159)
- **deps-gradle**: deleted dead `GradleError::{InvalidDependency, Maven, Io}` variants, never constructed outside tests (resolves #171)
- **Breaking (pre-1.0, internal API)**: deleted the legacy `deps_core::parser::{DependencyInfo, ManifestParser, ParseResultInfo}` traits, dead since the `ecosystem::{Dependency, ParseResult}` migration; `deps-pypi`'s `features()` extras mapping, lost in the deletion, was restored (resolves #139)
- **Breaking (pre-1.0, public API)**: removed the unused `serde::Serialize` derive from `deps-go`'s `GoDependency`/`GoParseResult`/`GoDirective` (resolves #195)
- **Breaking (pre-1.0, public API)**: deleted `Registry::package_url` (hover/completion always used `EcosystemFormatter::package_url`); removed from the trait and all 11 registries (resolves #213) (#328)

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

[Unreleased]: https://github.com/bug-ops/deps-lsp/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/bug-ops/deps-lsp/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/bug-ops/deps-lsp/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/bug-ops/deps-lsp/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/bug-ops/deps-lsp/compare/v0.14.0...v1.0.0
[0.14.0]: https://github.com/bug-ops/deps-lsp/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/bug-ops/deps-lsp/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/bug-ops/deps-lsp/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/bug-ops/deps-lsp/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/bug-ops/deps-lsp/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/bug-ops/deps-lsp/compare/v0.10.1...v0.11.0
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

---
aliases:
  - Specifications Index
  - Specs Overview
tags:
  - moc
  - sdd
created: 2026-08-19
status: moc
---

# Specifications

> [!abstract]
> Map of Content for all project specifications. Each entry links to
> a feature spec with its current phase and status.

## Active Specs

| ID | Feature | Phase | Status |
|----|---------|-------|--------|
| 001 | [[001-yaml-rust2-saphyr-eval/spec\|Evaluate saphyr as eventual successor to yaml-rust2]] | specify | draft — recommendation: do not migrate now |
| 002 | [[002-osv-vulnerability-diagnostics/spec\|OSV vulnerability diagnostics]] | specify | draft |
| 003 | [[003-maven-legacy-version-sort/spec\|Fix Maven/Gradle version sort corrupted by legacy non-semver versions]] | specify | draft — bug, P1 |
| 002 | [[002-osv-vulnerability-diagnostics/spec\|Vulnerability-aware diagnostics via OSV.dev batch API]] | plan | draft — plan complete, 5 open `[NEEDS CLARIFICATION]` items block `/sdd tasks` |
| 004 | [[004-release-freshness-signal/spec\|Release-freshness signal for version recommendations]] | specify | draft — research/P2, 8 open `[NEEDS CLARIFICATION]` items |
| 006 | [[006-completion-prefix-quote-stripping/spec\|Strip JSON string-delimiter quote from fallback completion prefix]] | specify | draft — bug, P2, 2 open `[NEEDS CLARIFICATION]` items |
| 005 | [[005-completion-search-blocking-timeout/spec\|Bound latency of package-name completion fallback search]] | specify | draft — bug, P1, 4 open `[NEEDS CLARIFICATION]` items |
| 007 | [[007-lightweight-registry-metadata/spec\|Adopt lightweight registry metadata formats for npm and PyPI version lookups]] | specify | draft — enhancement, P2 |
| 007 | [[007-lightweight-registry-metadata/plan\|Adopt lightweight registry metadata formats for npm and PyPI version lookups]] | plan | draft — plan complete, 2 open `[NEEDS CLARIFICATION]` items block `/sdd tasks` |
| 008 | [[008-codelens-update-all-outdated/spec\|CodeLens support for "update all outdated dependencies" action]] | specify | draft — research/parity, P2, 7 open `[NEEDS CLARIFICATION]` items |
| 009 | [[009-pypi-requirements-txt/spec\|Support requirements.txt (pip family) in deps-pypi]] | specify | draft — enhancement/parity, P2, 7 open `[NEEDS CLARIFICATION]` items |
| 010 | [[010-license-hover-policy/spec\|License in hover + license-policy diagnostics]] | specify | draft — research/parity, P3, 13 open `[NEEDS CLARIFICATION]` items |
| 011 | [[011-deprecation-replacement-diagnostics/spec\|Deprecation/abandoned diagnostics with suggested replacement]] | specify | draft — research/parity, P3, 9 open `[NEEDS CLARIFICATION]` items |
| 012 | [[012-unsatisfiable-requirement-diagnostic/spec\|Diagnostic for requirements matching zero published versions]] | specify | draft — enhancement/parity, P3, 9 open `[NEEDS CLARIFICATION]` items |
| 013 | [[013-deno-jsr-ecosystem/spec\|New ecosystem: Deno/JSR (deno.json / deno.jsonc)]] | specify | draft — research/new ecosystem, P3, 10 open `[NEEDS CLARIFICATION]` items |
| 014 | [[014-github-actions-ecosystem/spec\|New ecosystem: GitHub Actions workflow uses: pins]] | specify | draft — research/new ecosystem, P4, 9 open `[NEEDS CLARIFICATION]` items |
| 015 | [[015-lsp-3-18-diagnostic-markup-tooltip-gap/spec\|LSP 3.18 diagnostic markup / command-tooltip support blocked by ls-types 0.0.6]] | specify | draft — research/dependency-gap, P4, 3 open `[NEEDS CLARIFICATION]` items, blocked on upstream — no `/sdd plan` |
| 016 | [[016-bundler-platform-duplicate-versions/spec\|Deduplicate RubyGems platform-variant versions in Bundler hover]] | specify | draft — bug, P1, 3 open `[NEEDS CLARIFICATION]` items |
| 017 | [[017-hover-latest-marker-prerelease-mismatch/spec\|Hover "Recent versions" `(latest)` marker can disagree with the header's `Latest` field]] | specify | draft — bug, P2, 2 open `[NEEDS CLARIFICATION]` items |
| 018 | [[018-clippy-dashmap-await-guard/spec\|Add clippy.toml await-holding-invalid-types config for DashMap Ref guards]] | plan | draft — tooling/enhancement, P2, 2 open `[NEEDS CLARIFICATION]` items, plan complete |
| 019 | [[019-npm-all-deprecated-unknown-package/spec\|npm/JSR packages whose every published version is deprecated must not be reported "Unknown package"]] | specify | draft — bug, P1, 2 open `[NEEDS CLARIFICATION]` items |
| 020 | [[020-freshness-cooldown-diagnostics-blind/spec\|Release-cooldown callout never reaches diagnostics for registries that gate freshness behind get_versions_with]] | specify | draft — bug, P1, 1 open `[NEEDS CLARIFICATION]` item |
| 021 | [[021-maven-wildcard-latest-ignores-prerelease/spec\|Maven/Gradle "Newer version available" diagnostic and quick-fix must not recommend a prerelease when a stable release is newer]] | specify | draft — bug, P1, 1 open `[NEEDS CLARIFICATION]` item |
| 022 | [[022-pypi-package-completion-broken/spec\|PyPI package-name completion never returns results for any valid pyproject.toml shape]] | specify | draft — bug, P1, 2 open `[NEEDS CLARIFICATION]` items |
| 023 | [[023-cargo-custom-registries/spec\|Cargo custom/private registry & source-replacement resolution]] | specify | shipped — enhancement/security, P4 (PR 1a #440, PR 1b #447) |
| 023 | [[023-cargo-custom-registries/plan\|Cargo custom/private registry & source-replacement resolution]] | plan | shipped — 1a/1b PR sequencing delivered as PR #440 and PR #447 |
| 024 | [[024-net-policy-dns-rebinding/spec\|DNS-rebinding bypass of the workspace-registry SSRF host classifier (net_policy)]] | specify | shipped — security-hardening, P3, closed in two stages (PR #457 issue #449, PR #460 issue #455) |
| 025 | [[025-osv-fix-target-scan-gap/spec\|OSV fix-target scan gap — recommended fix version is never independently scanned]] | specify | draft — bug, P2, 4 open `[NEEDS CLARIFICATION]` items |
| 026 | [[026-deno-npm-yanked-diagnostic-alignment/spec\|Align Deno npm: yanked diagnostic with npm's suppressed behavior]] | specify | shipped — bug, P2 (PR #456, issue #448) |
| 027 | [[027-nuget-unlisted-version-and-multiproject-lockfile/spec\|NuGet unlisted-version hover marker and multi-project lock file matching]] | specify | shipped — bug, P2 (PR #458, issue #451) |
| 028 | [[028-pypi-requirements-documentlinks-and-directory-layout/spec\|PyPI requirements.txt -r/-c documentLinks and requirements/*.txt directory-layout recognition]] | specify | shipped — enhancement/security-hardening, P3 (PR #458, issue #452) |
| 029 | [[029-deno-jsr-yanked-exact-pin-restriction-drop/spec\|Drop the jsr: exact-pin-only restriction on the Deno yanked diagnostic]] | specify | shipped — bug, P2 (PR #459, issue #454) |
| 030 | [[030-gitlab-ci-ecosystem/spec\|New ecosystem: GitLab CI/CD include: version pins]] | specify | draft — research/new ecosystem, P4, 8 open `[NEEDS CLARIFICATION]` items, blocked on #208 (issue #466 tracks implementation) |
| 031 | [[031-github-actions-sha-pin-diagnostic/spec\|GitHub Actions mutable-ref-pin security diagnostic (SHA-pin recommendation)]] | tasks | implemented — research/parity, P2, awaiting merge (PR #477, issue #473) |
| 032 | [[032-npm-npmrc-registry-support/spec\|npm .npmrc custom/private registry support (scoped registries + top-level registry=)]] | plan | implemented — research/enhancement, P3, awaiting merge (PR #510, issue #502) |
| 033 | [[033-pypi-private-index-support/spec\|PyPI private/custom index resolution (--index-url / --extra-index-url / Poetry source / uv index)]] | tasks | shipped — research/enhancement, P3 (PR #516, issue #513) |
| 034 | [[034-go-goproxy-private-registry/spec\|Go GOPROXY/GOPRIVATE module proxy resolution]] | specify | draft — research/enhancement, P3 |
| 035 | [[035-nuget-private-feed-support/spec\|NuGet private/custom feed support (NuGet.Config packageSources)]] | specify | research/parity, P3, 3 open `[NEEDS CLARIFICATION]` items (issue #523) |
| 036 | [[036-composer-uppercase-v-prefix-bug/spec\|Composer requirement matching fails for uppercase-V-prefixed versions]] | specify | implemented — bug, P1, awaiting merge (issue #534) |
| 037 | [[037-supply-chain-trust-signal/spec\|Supply-chain trust signal (OpenSSF Scorecard + SLSA provenance) via deps.dev]] | specify | draft — research/parity, P3, 5 open `[NEEDS CLARIFICATION]` items |
| 038 | [[038-workspace-diagnostics-pull-support/spec\|Workspace Diagnostics Pull Support]] | specify | draft — research/enhancement, P4, 4 open `[NEEDS CLARIFICATION]` items (issue #547) |

## Completed Specs

(none yet)

## Project Foundation

- [[constitution]] — non-negotiable project principles (not yet created)

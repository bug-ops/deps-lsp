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
| 008 | [[008-codelens-update-all-outdated/spec\|CodeLens support for "update all outdated dependencies" action]] | specify | draft — research/parity, P2, 7 open `[NEEDS CLARIFICATION]` items |
| 015 | [[015-lsp-3-18-diagnostic-markup-tooltip-gap/spec\|LSP 3.18 diagnostic markup / command-tooltip support blocked by ls-types 0.0.6]] | specify | draft — research/dependency-gap, P4, 3 open `[NEEDS CLARIFICATION]` items, blocked on upstream — no `/sdd plan` (issue #308) |
| 025 | [[025-osv-fix-target-scan-gap/spec\|OSV fix-target scan gap — recommended fix version is never independently scanned]] | specify | draft — bug, P2, 4 open `[NEEDS CLARIFICATION]` items |
| 038 | [[038-workspace-diagnostics-pull-support/spec\|Workspace Diagnostics Pull Support]] | specify | parked — research/enhancement, P4, adoption-question resolved 2026-09-08 (wait for client support), 3 open plan-level `[NEEDS CLARIFICATION]` items remain moot until revisited (issue #547) |
| 042 | [[042-docker-base-image-ecosystem/spec\|New ecosystem: Dockerfile FROM base-image tag/digest freshness]] | specify | draft — research/new ecosystem, P4, 5 open `[NEEDS CLARIFICATION]` items, no user demand signal (issue #557) |
| 044 | [[044-precommit-hooks-ecosystem/spec\|New ecosystem: pre-commit hooks (.pre-commit-config.yaml repo/rev pins)]] | specify | draft — research/new ecosystem, P4, 6 open `[NEEDS CLARIFICATION]` items, tracked in issue #575 |
| 047 | [[047-elixir-hex-ecosystem/spec\|New ecosystem: Elixir Hex (mix.exs dependency version hints)]] | specify | draft — research/new-ecosystem, P4, 6 open `[NEEDS CLARIFICATION]` items, issue #642 |
| 051 | [[051-disk-persistent-registry-cache/spec\|Disk-persistent registry cache]] | specify | draft — research/enhancement, P4, 9 open `[NEEDS CLARIFICATION]` items, tracked in issue #700 |

## Completed Specs

| ID | Feature | Phase | Status |
|----|---------|-------|--------|
| 001 | [[001-yaml-rust2-saphyr-eval/spec\|Evaluate saphyr as eventual successor to yaml-rust2]] | specify | shipped — research/decision-record, recommendation: do not migrate now (no PR — spec is the artifact) |
| 002 | [[002-osv-vulnerability-diagnostics/spec\|OSV vulnerability diagnostics]] | specify | shipped — research/enhancement, P4 (PR #215, issue #124) |
| 002 | [[002-osv-vulnerability-diagnostics/plan\|Vulnerability-aware diagnostics via OSV.dev batch API]] | plan | shipped — plan delivered via PR #215 |
| 003 | [[003-maven-legacy-version-sort/spec\|Fix Maven/Gradle version sort corrupted by legacy non-semver versions]] | specify | shipped — bug, P1 (PR #128, issue #125) |
| 004 | [[004-release-freshness-signal/spec\|Release-freshness signal for version recommendations]] | specify | shipped — research/enhancement, P4, multi-stage rollout (PR #219 issue #145; extended by #220/#222/#294, #221/#225/#277, #293, #316) |
| 005 | [[005-completion-search-blocking-timeout/spec\|Bound latency of package-name completion fallback search]] | specify | shipped — bug, P1 (PR #154, issue #147) |
| 006 | [[006-completion-prefix-quote-stripping/spec\|Strip JSON string-delimiter quote from fallback completion prefix]] | specify | shipped — bug, P2 (PR #154, issue #148) |
| 007 | [[007-lightweight-registry-metadata/spec\|Adopt lightweight registry metadata formats for npm and PyPI version lookups]] | specify | shipped — enhancement, P2 (PR #168, issue #162) |
| 007 | [[007-lightweight-registry-metadata/plan\|Adopt lightweight registry metadata formats for npm and PyPI version lookups]] | plan | shipped — enhancement, P2 (PR #168, issue #162) |
| 009 | [[009-pypi-requirements-txt/spec\|Support requirements.txt (pip family) in deps-pypi]] | specify | shipped — enhancement/parity, P2 (PR #234, issue #203) |
| 010 | [[010-license-hover-policy/spec\|License in hover + license-policy diagnostics]] | plan | shipped — research/parity, P4 (PR #663 issue #204, PR #682 issues #660/#661, PR #665 issue #662) |
| 011 | [[011-deprecation-replacement-diagnostics/spec\|Deprecation/abandoned diagnostics with suggested replacement]] | specify | shipped — research/parity, P4 (PR #435, issue #205) |
| 012 | [[012-unsatisfiable-requirement-diagnostic/spec\|Diagnostic for requirements matching zero published versions]] | specify | shipped — enhancement/parity, P3 (PR #256, issue #206) |
| 013 | [[013-deno-jsr-ecosystem/spec\|New ecosystem: Deno/JSR (deno.json / deno.jsonc)]] | specify | shipped — research/new ecosystem, P3 (PR #309, issue #207) |
| 014 | [[014-github-actions-ecosystem/spec\|New ecosystem: GitHub Actions workflow uses: pins]] | specify | shipped — research/new ecosystem, P4 (PR #471, issue #208) |
| 016 | [[016-bundler-platform-duplicate-versions/spec\|Deduplicate RubyGems platform-variant versions in Bundler hover]] | specify | shipped — bug, P1 (PR #321, issue #311) |
| 017 | [[017-hover-latest-marker-prerelease-mismatch/spec\|Hover "Recent versions" `(latest)` marker can disagree with the header's `Latest` field]] | specify | shipped — bug, P2 (PR #321, issue #313) |
| 018 | [[018-clippy-dashmap-await-guard/spec\|Add clippy.toml await-holding-invalid-types config for DashMap Ref guards]] | plan | shipped — tooling/enhancement, P2 (PR #354, issue #334) |
| 019 | [[019-npm-all-deprecated-unknown-package/spec\|npm/JSR packages whose every published version is deprecated must not be reported "Unknown package"]] | specify | shipped — bug, P1 (PR #352, issue #338) |
| 020 | [[020-freshness-cooldown-diagnostics-blind/spec\|Release-cooldown callout never reaches diagnostics for registries that gate freshness behind get_versions_with]] | specify | shipped — bug, P1 (PR #352, issue #339) |
| 021 | [[021-maven-wildcard-latest-ignores-prerelease/spec\|Maven/Gradle "Newer version available" diagnostic and quick-fix must not recommend a prerelease when a stable release is newer]] | specify | shipped — bug, P1 (PR #352, issue #340) |
| 022 | [[022-pypi-package-completion-broken/spec\|PyPI package-name completion never returns results for any valid pyproject.toml shape]] | specify | shipped — bug, P1 (PR #397, issue #390) |
| 023 | [[023-cargo-custom-registries/spec\|Cargo custom/private registry & source-replacement resolution]] | specify | shipped — enhancement/security, P4 (PR 1a #440, PR 1b #447) |
| 023 | [[023-cargo-custom-registries/plan\|Cargo custom/private registry & source-replacement resolution]] | plan | shipped — 1a/1b PR sequencing delivered as PR #440 and PR #447 |
| 024 | [[024-net-policy-dns-rebinding/spec\|DNS-rebinding bypass of the workspace-registry SSRF host classifier (net_policy)]] | specify | shipped — security-hardening, P3, closed in two stages (PR #457 issue #449, PR #460 issue #455) |
| 026 | [[026-deno-npm-yanked-diagnostic-alignment/spec\|Align Deno npm: yanked diagnostic with npm's suppressed behavior]] | specify | shipped — bug, P2 (PR #456, issue #448) |
| 027 | [[027-nuget-unlisted-version-and-multiproject-lockfile/spec\|NuGet unlisted-version hover marker and multi-project lock file matching]] | specify | shipped — bug, P2 (PR #458, issue #451) |
| 028 | [[028-pypi-requirements-documentlinks-and-directory-layout/spec\|PyPI requirements.txt -r/-c documentLinks and requirements/*.txt directory-layout recognition]] | specify | shipped — enhancement/security-hardening, P3 (PR #458, issue #452) |
| 029 | [[029-deno-jsr-yanked-exact-pin-restriction-drop/spec\|Drop the jsr: exact-pin-only restriction on the Deno yanked diagnostic]] | specify | shipped — bug, P2 (PR #459, issue #454) |
| 030 | [[030-gitlab-ci-ecosystem/spec\|New ecosystem: GitLab CI/CD include: version pins]] | plan | shipped — research/new ecosystem, P4 (PR #596, issue #466) |
| 031 | [[031-github-actions-sha-pin-diagnostic/spec\|GitHub Actions mutable-ref-pin security diagnostic (SHA-pin recommendation)]] | tasks | shipped — research/parity, P2 (PR #477, issue #473) |
| 032 | [[032-npm-npmrc-registry-support/spec\|npm .npmrc custom/private registry support (scoped registries + top-level registry=)]] | plan | shipped — research/enhancement, P3 (PR #510, issue #502) |
| 033 | [[033-pypi-private-index-support/spec\|PyPI private/custom index resolution (--index-url / --extra-index-url / Poetry source / uv index)]] | tasks | shipped — research/enhancement, P3 (PR #516, issue #513) |
| 034 | [[034-go-goproxy-private-registry/spec\|Go GOPROXY/GOPRIVATE module proxy resolution]] | specify | shipped — research/enhancement, P3 (PR #558, issue #519) |
| 035 | [[035-nuget-private-feed-support/spec\|NuGet private/custom feed support (NuGet.Config packageSources)]] | specify | shipped — research/parity, P3 (PR #560, issue #523) |
| 036 | [[036-composer-uppercase-v-prefix-bug/spec\|Composer requirement matching fails for uppercase-V-prefixed versions]] | specify | shipped — bug, P1 (PR #538, issue #534) |
| 037 | [[037-supply-chain-trust-signal/spec\|Supply-chain trust signal (OpenSSF Scorecard + SLSA provenance) via deps.dev]] | plan | shipped — research/parity, P3 (PR #554, issue #543) |
| 039 | [[039-github-rate-limit-actionable-diagnostic/spec\|Actionable rate-limit hint in registry diagnostics]] | specify | shipped — bug, P1 (PR #485, issue #478) |
| 040 | [[040-github-token-redaction-trusted-origin-pin/spec\|GitHub auth token redaction and trusted-origin pinning]] | specify | shipped — security/hardening, P3 (PR #487, issue #484) |
| 041 | [[041-credential-redaction-hardening/spec\|Redact user:pass@ credentials from registry-index logs and errors]] | specify | shipped — security, P2, two stages (PR #529 issue #522, PR #540 issue #536) |
| 043 | [[043-nuget-feed-authentication/spec\|NuGet Feed Authentication (credentialed NuGet.Config sources)]] | specify | shipped — enhancement/security, P3 (PR #572, issues #561, #562) |
| 045 | [[045-secret-accessor-auditable-naming/spec\|Rename Redacted<T>/wrapper as_str() secret accessors to an auditable name]] | specify | shipped — enhancement/security, P3 (PR #582, issue #581) |
| 046 | [[046-pnpm-catalogs/spec\|pnpm catalogs + workspace: protocol resolution support]] | specify | shipped — research/enhancement, P3 (PR #589, issue #587) |
| 048 | [[048-gitlab-ci-mutable-pin-message-contradicts-quickfix/spec\|GitLab CI mutable-ref-pin diagnostic wrongly claims no automated fix for component Latest/Partial pins]] | specify | shipped — bug, P2 (PR #645, issues #640, #643) |
| 049 | [[049-osv-malicious-package-severity/spec\|OSV malicious-package (MAL-*) advisory severity distinguishing]] | specify | shipped — research/correctness, P2 (PR #652, issue #646) |
| 050 | [[050-cargo-renamed-dependency-lockfile-resolution/spec\|Per-occurrence lockfile version resolution for renamed/aliased dependencies]] | specify | shipped — bug, P1 (PR #653, issue #649) |
| 052 | [[052-pnpm-lockfile-provider/spec\|pnpm-lock.yaml lock file provider (npm ecosystem)]] | specify | shipped — enhancement/cross-ecosystem, P3 (PR #719, issue #709; scoped to pnpm-lock.yaml only) |
| 053 | [[053-ecosystem-sealing-inversion-decision-record/spec\|Ecosystem sealing inversion decision record]] | specify | shipped — research/decision-record, P4, won't-do, spec is the artifact (issue #774 to be closed referencing this spec) |
| 054 | [[054-redacted-url-structural-chokepoint/spec\|Structural chokepoint for outbound-URL redaction in error/log output]] | specify | shipped — enhancement/security, P2 (PR #800 issue #789, PR #807 issue #801) — follow-up to #767/#775 |

## Project Foundation

- [[constitution]] — non-negotiable project principles
